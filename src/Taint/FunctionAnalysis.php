<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\IncludeGraph;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Fingerprint;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Registry\ArgumentSelector;
use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\MatcherKind;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\Sanitizer;
use Enshrined\WpTaint\Registry\Sink;
use Enshrined\WpTaint\Registry\Source;
use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * One run of the propagation loop over one function body.
 *
 * SSA is what keeps this small. Def-use chains already exist, phi nodes already
 * merge branches, so propagation is a transfer function applied to each op until
 * nothing changes. If this file starts growing past a few hundred lines of
 * actual logic, the design has drifted and the extra work belongs in a
 * collaborator, not here.
 */
final class FunctionAnalysis
{
    /**
     * Deliberately overlaps `wp.sqli.wpdb-query`. When both fire on the same
     * line the taint finding wins — see
     * {@see \Enshrined\WpTaint\Finding\FindingCollection::withRulePrecedence()}.
     */
    private const UNPREPARED_QUERY_RULE = 'wp.sqli.unprepared-query';

    /** How far {@see throughAssignments} follows `$a = $b = $c` before giving up. */
    private const MAX_ASSIGNMENT_HOPS = 16;

    /**
     * Properties the seeded parameter reached, keyed to deduplicate.
     *
     * @var array<string, array{0: string|null, 1: string}>
     */
    private array $propertiesReached = [];

    private TaintState $state;

    private ClassTypeMap $types;

    /** @var list<Finding> */
    private array $findings = [];

    /** @var list<SinkReference> */
    private array $sinksReached = [];

    /** @var array<string, true> */
    private array $emitted = [];

    private TaintSet $returnTaint;

    /** Null until the first return is seen; then AND-ed across every return. */
    private ?bool $returnAnchored = null;

    private bool $imprecise = false;

    /** @var list<AnalysisWarning> */
    private array $warnings = [];

    private readonly QueryShapeInspector $queryShapes;

    private readonly LiteralAnchor $anchors;

    private readonly GuardAnalyzer $guards;

    /** The block being walked, so a sink can ask what guarded the path to it. */
    private ?Block $currentBlock = null;

    /** The call currently being reported on, for sink strategies that need it. */
    private ?CallTarget $sinkCall = null;

    /** A hook dispatch whose result should lose any escaping its arguments carried. */
    private ?CallTarget $voidingCall = null;

    /**
     * The op of {@see $voidingCall}, kept so the trace can point at it.
     *
     * Without it the finding said "this value was escaped and then filtered"
     * and the trace showed the escape and the echo and nothing in between, so
     * the one question a reader has — filtered *where*? — had no answer in the
     * output.
     */
    private ?Op\Expr $voidingOp = null;


    private bool $collecting = false;

    /**
     * Set while a call op with several possible callees is being transferred,
     * so their results accumulate on the shared operand instead of the last one
     * visited overwriting the rest. See {@see transferCalls()}.
     */
    private bool $unionResultWrites = false;

    /**
     * Where the callee currently being transferred writes its return value. A
     * dispatcher decides this; see {@see CallResultMode}.
     */
    private CallResultMode $resultMode = CallResultMode::Value;

    /**
     * Pairs of operands that name the same storage.
     *
     * `$a = &$b` and `foreach ( $x as &$v )` both make two names for one slot
     * for the rest of the function, and SSA has no way to say so — it versions
     * assignments, not aliases. Rather than teach every write about aliasing,
     * each pass ends by unioning taint across the pairs.
     *
     * @var list<array{0: Operand, 1: Operand, 2: bool}> the two operands, and whether the link is into the
     *                                                   element slot rather than the value
     */
    private array $aliases = [];

    /** Set when a pair is discovered, so the pass that found it reports a change. */
    private bool $aliasChanged = false;

    /** Distinguishes several include sites sharing one line. Reset each pass. */
    private int $includeOffset = 0;

    /** The same, for template calls, which have their own key space. */
    private int $templateOffset = 0;

    /**
     * Every named operand in the body, grouped by variable name.
     *
     * An alias binds a *variable*, not one SSA version of it. `foreach ( $x as
     * &$v )` lowers to an `AssignRef` onto `$v`, and the `$v = …` inside the
     * loop writes a different version; without grouping by name the link breaks
     * at exactly the write that matters.
     *
     * Over-approximate by construction — a name aliased anywhere is treated as
     * aliased throughout the function — and contained, because PHP variables
     * are function-scoped anyway.
     *
     * @var array<string, list<Operand>>
     */
    private array $operandsByName = [];

    /**
     * Iterator values bound by reference, paired with the collection they write
     * back into. Consumed by the `AssignRef` that names the loop variable.
     *
     * @var list<array{0: Operand, 1: Operand}>
     */
    private array $writesBackInto = [];

    private TraceBuilder $traces;

    /** @var list<Block> */
    private array $blocks;

    public function __construct(
        private readonly FunctionContext $context,
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
        private readonly CallResolver $resolver,
        private readonly LiteralAnalyzer $literals,
        private readonly SummaryTable $summaries,
        private readonly PropertyTaintMap $properties,
        private readonly ScopeTable $scopes,
        private readonly ?IncludeGraph $includes,
        private readonly ReceiverResolver $receivers,
        private readonly AnalysisOptions $options,
        private readonly ?int $seedParameterIndex,
        private readonly bool $collectFindings,
        private readonly ?CallGraph $callGraph = null,
        /** @var array<string, true> */
        private readonly array $shortcodeCallbacks = [],
        /** @var array<string, string> */
        private readonly array $printedReturns = [],
    ) {
        $this->state = new TaintState();
        $this->types = new ClassTypeMap();
        $this->queryShapes = new QueryShapeInspector(
            $literals,
            new OriginClassifier($registry, $resolver, $properties, $receivers),
        );
        $this->anchors = new LiteralAnchor(
            $summaries,
            $resolver,
            $properties,
            $receivers,
            $context,
            $this->types,
            $registry,
        );
        $this->guards = new GuardAnalyzer();
        $this->returnTaint = TaintSet::empty();
        $this->returnAnchored = null;
        $this->blocks = BlockOrder::of($this->context->func->cfg);
        $this->guards->forFunction($this->blocks);
        $this->traces = new TraceBuilder(
            $this->state,
            $this->context->file->sourceMap,
            $this->context->file->relativePath,
            $this->options->maxTraceSteps,
        );
    }

    public function run(): AnalysisResult
    {
        $this->types->seedFromFunction($this->context);
        $this->seedSources();
        $this->seedIncludedScope();
        $this->seedCapturedScope();
        $this->seedByReferenceCaptures();
        $this->seedIncludeResults();

        $debug = getenv('WP_TAINT_DEBUG') !== false;

        if ($debug) {
            $this->state->countChanges();
        }

        $iterations = 0;

        do {
            $changed = $this->pass();
            $iterations++;
        } while ($changed && $iterations < $this->options->maxIterations);

        $this->publishScope();

        if ($changed) {
            // In a debug run, non-convergence is a bug in this engine, not a
            // note to the user: throw and name the operand two ops cannot agree
            // on, which is the disease every historical incident shared and
            // which used to be found only by a slow scan. The fixture suite
            // runs with WP_TAINT_DEBUG set, so the next change that reintroduces
            // it fails a test instead of shipping.
            if ($debug) {
                throw new NonConvergenceError($this->describeOscillation($iterations));
            }

            $this->warnings[] = new AnalysisWarning(
                $this->context->file->relativePath,
                $this->context->displayName,
                sprintf(
                    'Taint fixed point did not converge within %d iterations. Results for this function may be '
                        . 'incomplete.',
                    $this->options->maxIterations,
                ),
            );
        }

        // Findings and sink references come from one final pass over the
        // converged state, so a sink is never reported twice with a
        // half-propagated trace behind it.
        $this->collecting = true;
        $this->pass();

        return new AnalysisResult(
            $this->findings,
            $this->returnTaint,
            $this->sinksReached,
            $this->imprecise,
            $this->byRefTaint(),
            $this->warnings,
            $this->state,
            $this->returnAnchored ?? false,
            array_values($this->propertiesReached),
        );
    }

    /**
     * Superglobals are the only sources that are not calls, so they are seeded
     * up front by walking every operand the function mentions.
     */
    /**
     * Publish what a file's top-level code leaves in its variables.
     *
     * The other half of the join. An includer reads this back after the include,
     * which is how a config partial works: `include 'config.php'` and the
     * settings it assigned are in scope afterwards.
     *
     * Only names this file *assigns*. A variable that merely passed through —
     * seeded in by an includer and never touched — is not something this file
     * produced.
     */
    private function publishScope(): void
    {
        // Closures as well as file-level code. A closure that captured a
        // variable by reference writes back out to the scope that made it, and
        // the only way the maker can learn what it wrote is if the closure says
        // so. Nothing reads a closure's key from this table except
        // {@see seedByReferenceCaptures}: the include machinery asks for
        // `::{main}` keys only.
        if (! $this->context->isMain() && ! $this->context->isClosure()) {
            return;
        }

        $assigned = $this->assignedNames();

        if ($assigned === []) {
            return;
        }

        $named = $this->namedScopeWithOrigins();
        $scope = [];
        $origins = [];

        foreach ($named['taint'] as $name => $taint) {
            if (! isset($assigned[$name])) {
                continue;
            }

            $scope[$name] = $taint;

            if (isset($named['origins'][$name])) {
                $origins[$name] = $named['origins'][$name];
            }
        }

        $this->scopes->addOutOf($this->context->key, $scope, $origins);
    }

    /**
     * Names this body assigns to, as a set.
     *
     * @return array<string, true>
     */
    private function assignedNames(): array
    {
        $names = [];

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\Assign && ! $op instanceof Op\Expr\AssignRef) {
                    continue;
                }

                $name = OperandHelper::variableName($op->var);

                if ($name !== null) {
                    $names[$name] = true;
                }
            }
        }

        return $names;
    }

    /**
     * Start a file's top-level code with whatever its includers had in scope.
     *
     * An include shares the includer's variables, so `template.php` opens with
     * `$title` already holding whatever the file that included it put there.
     * Only `{main}` bodies: a function has its own scope and an include inside
     * one shares *that*, which the site-level join below handles.
     */
    /**
     * What a closure captured, put onto its body's free variables.
     *
     * Published by {@see transferClosure} at the site that created it.
     */
    private function seedCapturedScope(): void
    {
        if ($this->context->isMain()) {
            return;
        }

        $this->seedScope(
            $this->scopes->scopeInto($this->context->key),
            '$%s was captured by this closure through its use clause.',
            $this->context->key,
        );
    }

    /**
     * What a closure wrote back through a by-reference capture.
     *
     *     $message = '';
     *     add_action( 'init',   function () use ( &$message ) {
     *         $message = wp_unslash( $_POST['m'] );
     *     } );
     *     add_action( 'render', function () use ( &$message ) {
     *         echo $message;                              // reported
     *     } );
     *
     * `use ( &$x )` is a two-way binding and only one way was modelled. The
     * first closure's write never left it, so the second closure captured an
     * empty string and the echo was clean.
     *
     * Round by round: the writing closure publishes, the enclosing scope picks
     * it up here, and the reading closure receives it through the ordinary
     * by-value capture on the round after that. It only ever adds, so the fixed
     * point stays monotone.
     *
     * By-value captures are left alone. `use ( $x )` copies, and a write inside
     * the closure is invisible outside it — which is the whole difference.
     */
    private function seedByReferenceCaptures(): void
    {
        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\Closure) {
                    continue;
                }

                $key = FunctionContext::keyFor($op->func, $this->context->file);
                $written = $this->scopes->scopeOutOf($key);

                if ($written === []) {
                    continue;
                }

                $scope = [];

                foreach ($op->useVars as $captured) {
                    if (! $captured instanceof Operand\BoundVariable || $captured->byRef !== true) {
                        continue;
                    }

                    $name = OperandHelper::variableName($captured);

                    if ($name !== null && isset($written[$name])) {
                        $scope[$name] = $written[$name];
                    }
                }

                if ($scope !== []) {
                    $this->seedScope(
                        $scope,
                        '$%s was written by a closure that captured it by reference.',
                        $key,
                    );
                }
            }
        }
    }

    private function seedIncludedScope(): void
    {
        if (! $this->context->isMain()) {
            return;
        }

        $this->seedScope(
            $this->scopes->scopeInto($this->context->key),
            '$%s was in scope at the include that loaded this file.',
            $this->context->key,
        );
    }

    /**
     * Put a scope onto this body's named variables, once.
     *
     * Before the propagation loop, never during it. A variable seeded here is
     * still owned by whatever assigns it: if the included file sets `$title`
     * itself, that assignment wins, which is exactly right.
     *
     * @param array<string, TaintSet> $scope
     */
    private function seedScope(array $scope, string $description, string $originKey): void
    {
        if ($scope === []) {
            return;
        }

        $keyed = $this->scopes->keyedInto($originKey);

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op) {
                    continue;
                }

                foreach (OperandHelper::operandsOf($op) as $operand) {
                    $name = OperandHelper::variableName($operand);

                    if ($name === null || ! isset($scope[$name])) {
                        continue;
                    }

                    $provenance = new Provenance(
                        TraceVerb::Propagate,
                        $op,
                        sprintf($description, $name),
                        prefix: $this->scopes->originOf($originKey, $name),
                    );

                    // Per-key first: when the caller's array had precise keys,
                    // seeding only the flat union would throw that away at the
                    // boundary and every key would read as tainted again.
                    $keys = $keyed[$name] ?? [];

                    if ($keys !== []) {
                        foreach ($keys as $index => $taint) {
                            $this->state->addKeyedTaint($operand, $index, $taint, $provenance);
                        }

                        continue;
                    }

                    $this->state->add($operand, $scope[$name], $provenance);
                }
            }
        }
    }

    /**
     * Join the includer's scope to the included file's, both ways.
     *
     * PHP includes share the includer's variables, which is the whole reason
     * the theme shape works — `$title = $_GET['title']; include 'tpl.php';` and
     * the template echoes `$title`. Nothing in the call machinery models that:
     * a call has positional parameters, an include has the caller's entire
     * scope.
     *
     * Out, then back. The out half lands in the shared {@see ScopeTable}, which
     * the interprocedural loop iterates to a fixed point exactly as it does the
     * property map. The back half reads the includee's scope from that same
     * table rather than descending into it, so an include cycle terminates.
     */
    private function joinIncludedScope(Op\Expr\Include_ $op): bool
    {
        if ($this->includes === null) {
            return false;
        }

        $site = IncludeGraph::siteKey(
            $this->context->file->relativePath,
            $op->getLine(),
            $this->includeOffset++,
        );

        $targets = $this->includes->targetsFor($site);

        if ($targets === []) {
            // An include we cannot follow is a hole the size of the file behind
            // it, and the reader should know the engine stopped here.
            $this->imprecise = true;

            return false;
        }

        // Only the outbound half runs here, and it writes nothing this body
        // owns — just the shared table, which is union-only. The inbound halves
        // are one-time seeds before the loop: writing to a variable during a
        // pass would fight the assignment that owns that operand, which is how
        // this oscillated the first time.
        $changed = false;
        $visible = $this->namedScopeWithOrigins();

        foreach ($targets as $target) {
            $changed = $this->scopes->addInto(
                strtolower($target . '::{main}'),
                $visible['taint'],
                $visible['origins'],
            ) || $changed;
        }

        return $changed;
    }

    /**
     * Seed what each file this body includes left behind.
     *
     * `include 'config.php'` and the settings it assigned are in scope
     * afterwards. Read from the table rather than by descending into the
     * includee, so a cycle terminates; seeded once, before the loop, so no
     * assignment in this body has to fight it.
     */
    private function seedIncludeResults(): void
    {
        if ($this->includes === null) {
            return;
        }

        $offset = 0;

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\Include_) {
                    continue;
                }

                $site = IncludeGraph::siteKey(
                    $this->context->file->relativePath,
                    $op->getLine(),
                    $offset++,
                );

                foreach ($this->includes->targetsFor($site) as $target) {
                    $this->seedScope(
                        $this->scopes->scopeOutOf(strtolower($target . '::{main}')),
                        sprintf('$%%s was left in scope by %s.', $target),
                        strtolower($target . '::{main}'),
                    );
                }
            }
        }
    }

    /**
     * Every named variable this body holds taint in, with the trace of where
     * that taint came from.
     *
     * The trace is what stops a finding on the far side of an include from
     * beginning "$title was in scope" and ending there.
     *
     * @return array{taint: array<string, TaintSet>, origins: array<string, list<TraceStep>>}
     */
    private function namedScopeWithOrigins(): array
    {
        $scope = [];
        $origins = [];

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op) {
                    continue;
                }

                foreach (OperandHelper::operandsOf($op) as $operand) {
                    $name = OperandHelper::variableName($operand);

                    if ($name === null) {
                        continue;
                    }

                    $taint = $this->state->effectiveTaintOf($operand);

                    if ($taint->isEmpty()) {
                        continue;
                    }

                    $scope[$name] = ($scope[$name] ?? TaintSet::empty())->union($taint);

                    if (! isset($origins[$name])) {
                        $origin = $this->scopeTrace($op, $operand, $name, $taint);

                        if ($origin !== []) {
                            $origins[$name] = $origin;
                        }
                    }
                }
            }
        }

        return ['taint' => $scope, 'origins' => $origins];
    }

    /**
     * The trace that explains why a variable holds taint.
     *
     * Summary extraction seeds a parameter with every kind, which is a
     * hypothesis rather than a flow — the same reason property writes record no
     * origin during a summarising run.
     *
     * @return list<TraceStep>
     */
    private function scopeTrace(Op $op, Operand $operand, string $name, TaintSet $taint): array
    {
        if ($this->seedParameterIndex !== null) {
            return [];
        }

        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null) {
            return [];
        }

        $step = $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            sprintf('$%s holds this when the include runs.', $name),
        );

        return $this->traces->build($operand, $kind, $step);
    }

    private function seedSources(): void
    {
        foreach ($this->blocks as $block) {
            foreach ($block->phi as $phi) {
                $this->seedOperands(OperandHelper::operandsOf($phi));
            }

            foreach ($block->children as $op) {
                if ($op instanceof Op) {
                    $this->seedOperands(OperandHelper::operandsOf($op));
                }
            }
        }

        if ($this->seedParameterIndex === null) {
            $this->seedShortcodeParameters();
            $this->seedUnknownParameters();

            return;
        }

        $param = $this->context->func->params[$this->seedParameterIndex] ?? null;

        if (! $param instanceof Op\Expr\Param) {
            return;
        }

        $this->state->set(
            $param->result,
            TaintSet::allDataflowKinds(),
            new Provenance(
                TraceVerb::Source,
                $param,
                sprintf(
                    'Parameter %d (%s) of %s, assumed tainted while summarising the function.',
                    $this->seedParameterIndex,
                    $this->context->parameterName($this->seedParameterIndex),
                    $this->context->displayName,
                ),
            ),
        );
    }

    /**
     * A shortcode callback is handed post content.
     *
     *     add_shortcode( 'badge', 'acme_badge' );
     *     function acme_badge( $atts, $content = '' ) { … }
     *
     * `$atts` are the attributes written in the post body and `$content` is
     * what the tag wraps, so both are chosen by whoever could edit that post —
     * a contributor, on most sites. That is the same trust level as an option
     * or post meta, so they carry the same kinds a stored source does rather
     * than a request source's.
     *
     * `$tag` is the third parameter and is the shortcode's own name, which the
     * plugin chose, so it is left alone.
     */
    private function seedShortcodeParameters(): void
    {
        if (! isset($this->shortcodeCallbacks[$this->context->key])) {
            return;
        }

        $kinds = $this->registry->storedSourceKinds();

        foreach (array_slice(array_values($this->context->func->params), 0, 2) as $index => $param) {
            if (! $param instanceof Op\Expr\Param) {
                continue;
            }

            $this->state->add(
                $param->result,
                $kinds,
                new Provenance(
                    TraceVerb::Source,
                    $param,
                    sprintf(
                        'Parameter %d (%s) of a shortcode callback. Shortcode attributes and content come from '
                            . 'post content, which anyone who can edit a post chooses.',
                        $index,
                        $this->context->parameterName($index),
                    ),
                ),
            );
        }
    }

    /**
     * Mark every parameter as being of unknown provenance.
     *
     * Only on the findings pass, and only with {@see TaintKind::Unknown}, which
     * no ordinary rule reports. A caller that passes something tainted supplies
     * the real kinds through the summary; this says nothing about those, only
     * that the value did not originate here and nothing has vouched for it.
     */
    private function seedUnknownParameters(): void
    {
        if (! $this->options->unknownProvenance || ! $this->isEntryPoint()) {
            return;
        }

        foreach (array_values($this->context->func->params) as $index => $param) {
            if (! $param instanceof Op\Expr\Param) {
                continue;
            }

            $this->state->add(
                $param->result,
                TaintSet::of(TaintKind::Unknown),
                new Provenance(
                    TraceVerb::Source,
                    $param,
                    sprintf(
                        'Parameter %d (%s) of %s. Nothing in the scan says where this comes from, and nothing '
                            . 'has sanitised or escaped it.',
                        $index,
                        $this->context->parameterName($index),
                        $this->context->displayName,
                    ),
                ),
            );
        }
    }

    /**
     * Does this function's arguments arrive from outside the scanned code?
     *
     * Only then is a parameter's provenance actually unknown. Marking every
     * parameter meant marking ones the scan can answer for itself:
     *
     *     function acme_render( $title ) { echo $title; }
     *     acme_render( esc_html( $x ) );          // we can read this
     *
     * The caller settles that, and the summary already carries what it passed.
     * What is genuinely unknown is a function nothing in the scan calls — a
     * callback on a core hook, a public API a theme uses, a template WordPress
     * includes. The call graph already folds in hook dispatches, so a callback
     * whose `apply_filters()` we *can* see is not an entry point and its
     * arguments are read from the dispatch like any other call.
     *
     * With no graph, everything is an entry point, which is where this started.
     */
    private function isEntryPoint(): bool
    {
        return $this->callGraph === null || ! $this->callGraph->hasCaller($this->context->key);
    }

    /**
     * @param list<Operand> $operands
     */
    private function seedOperands(array $operands): void
    {
        foreach ($operands as $operand) {
            $name = OperandHelper::variableName($operand);

            if ($name === null) {
                continue;
            }

            $source = $this->registry->source(Matcher::superglobal($name));

            if ($source === null) {
                continue;
            }

            $this->state->set(
                $operand,
                $source->kinds,
                new Provenance(
                    TraceVerb::Source,
                    null,
                    sprintf('Tainted by superglobal $%s.', $name),
                ),
            );
        }
    }

    private function pass(): bool
    {
        $changed = false;

        $this->includeOffset = 0;
        $this->templateOffset = 0;

        foreach ($this->blocks as $block) {
            $this->currentBlock = $block;

            foreach ($block->phi as $phi) {
                $changed = $this->applyPhi($phi) || $changed;
            }

            foreach ($block->children as $op) {
                if (! $op instanceof Op) {
                    continue;
                }

                $this->types->observe($op, $this->context->className);

                $changed = $this->transfer($op) || $changed;
            }
        }

        return $this->mergeAliases() || $changed;
    }

    /**
     * Make every alias pair agree.
     *
     * Run once at the end of each pass rather than at each write, because the
     * two halves of an alias are written by ops that may be blocks apart and
     * neither knows about the other. Only ever grows, so it converges along with
     * everything else.
     */
    private function mergeAliases(): bool
    {
        $changed = $this->aliasChanged;
        $this->aliasChanged = false;

        foreach ($this->aliases as [$left, $right, $intoContainer]) {
            if ($intoContainer) {
                // Every SSA version of the bound variable, because the write
                // that matters — `$v = …` inside the loop — is a fresh version
                // that the binding itself never mentions.
                foreach ($this->versionsOf($left) as $value) {
                    $changed = $this->mergeElementAlias($value, $right) || $changed;
                }

                continue;
            }

            $changed = $this->mergeOperandAlias($left, $right) || $changed;
        }

        return $changed;
    }

    /**
     * Every SSA version of the variable an operand names, or just the operand
     * when it has no name.
     *
     * @return list<Operand>
     */
    private function versionsOf(Operand $operand): array
    {
        $name = OperandHelper::variableName($operand);

        if ($name === null) {
            return [$operand];
        }

        if ($this->operandsByName === []) {
            $this->indexOperandsByName();
        }

        return $this->operandsByName[$name] ?? [$operand];
    }

    private function indexOperandsByName(): void
    {
        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op) {
                    continue;
                }

                foreach (OperandHelper::operandsOf($op) as $operand) {
                    $name = OperandHelper::variableName($operand);

                    if ($name === null) {
                        continue;
                    }

                    if (! in_array($operand, $this->operandsByName[$name] ?? [], true)) {
                        $this->operandsByName[$name][] = $operand;
                    }
                }
            }
        }
    }

    /**
     * A loop variable bound by reference is one element of the collection: what
     * it holds belongs in the element slot, and what the collection holds comes
     * back out of it.
     */
    private function mergeElementAlias(Operand $value, Operand $collection): bool
    {
        $held = $this->state->effectiveTaintOf($value);

        if ($held->isEmpty()) {
            return false;
        }

        $provenance = $this->state->provenanceOf($value)
            ?? $this->state->containerProvenanceOf($value);

        if ($provenance === null) {
            return false;
        }

        // One way only. The collection's element slot is never *set* by
        // anything — writes into it all go through addContainerTaint, which
        // grows — so adding here cannot start a fight. Pushing back the other
        // way would, because an ordinary assignment to the loop variable owns
        // that operand and would reset it every pass.
        return $this->state->addContainerTaint($collection, $held, $provenance);
    }

    /**
     * `$a = &$b`: one slot under two names, both halves.
     */
    private function mergeOperandAlias(Operand $left, Operand $right): bool
    {
        $changed = false;
        $own = $this->state->taintOf($left)->union($this->state->taintOf($right));

        if (! $own->isEmpty()) {
            $provenance = $this->state->provenanceOf($left) ?? $this->state->provenanceOf($right);
            $changed = $this->state->add($left, $own, $provenance);
            $changed = $this->state->add($right, $own, $provenance) || $changed;
        }

        $elements = $this->state->containerTaintOf($left)->union($this->state->containerTaintOf($right));

        if (! $elements->isEmpty()) {
            $provenance = $this->state->containerProvenanceOf($left)
                ?? $this->state->containerProvenanceOf($right);

            if ($provenance !== null) {
                $changed = $this->state->addContainerTaint($left, $elements, $provenance) || $changed;
                $changed = $this->state->addContainerTaint($right, $elements, $provenance) || $changed;
            }
        }

        return $changed;
    }

    /**
     * Record that two operands name one slot. Idempotent: `pass()` walks the
     * same ops on every iteration.
     */
    private function alias(Operand $left, Operand $right, bool $intoContainer): void
    {
        foreach ($this->aliases as [$a, $b, $c]) {
            if ($a === $left && $b === $right && $c === $intoContainer) {
                return;
            }
        }

        $this->aliases[] = [$left, $right, $intoContainer];
        $this->aliasChanged = true;
    }

    /**
     * What each by-reference parameter holds once the body has settled.
     *
     * The callee's half of a write the caller can see. Both slots, because
     * `function fill( array &$out ) { $out[] = $_GET['x']; }` puts the taint in
     * the element slot and the caller reading `$out[0]` needs to find it.
     *
     * @return array<int, TaintSet>
     */
    private function byRefTaint(): array
    {
        $taint = [];

        foreach ($this->context->byRefParameters() as $index) {
            $operand = $this->context->parameterOperand($index);

            if ($operand === null) {
                continue;
            }

            $held = $this->state->effectiveTaintOf($operand);

            if (! $held->isEmpty()) {
                $taint[$index] = $held;
            }
        }

        return $taint;
    }

    /**
     * A phi node unions its incoming operands. This is the whole of the
     * engine's branch and loop handling: the IR did the hard part.
     */
    private function applyPhi(Op\Phi $phi): bool
    {
        $incoming = [];

        foreach ($phi->vars as $var) {
            if ($var instanceof Operand) {
                $incoming[] = $var;
            }
        }

        $merged = self::withoutSplitEscapeClaim($this->state->unionOf($incoming), $incoming, $this->state);

        if ($merged->isEmpty()) {
            return $this->state->set($phi->result, $merged);
        }

        return $this->state->set(
            $phi->result,
            $merged,
            new Provenance(
                TraceVerb::Propagate,
                $phi,
                'Branches merge here; the value carries the taint of whichever path was taken.',
                $incoming,
            ),
        );
    }

    /**
     * A union must not manufacture a claim neither branch made.
     *
     * `escape_voided` only reports alongside `escaped`: the pair says one value
     * was escaped and then handed to a filter. A phi can produce that pair from
     * two paths where neither did both:
     *
     *     if ( is_numeric( $media_id ) ) {
     *         $html = wp_get_attachment_image( $media_id, 'large' );   // voided
     *     }
     *     if ( '' === $html && $url ) {
     *         $html = sprintf( '<img src="%s">', esc_url( $url ) );    // escaped
     *     }
     *     echo $html;                                                  // reported
     *
     * The first branch never escaped anything and the second never went near a
     * filter. Three blocks in a real client theme are exactly this, all of them
     * the fallback-to-a-URL shape, and the finding tells the reader to fix an
     * ordering that no path has.
     *
     * So the pair survives a merge only when one incoming operand carried both.
     * `escaped` is the half dropped, because it is the marker that makes the
     * claim; `escape_voided` alone reports nothing and still records that a
     * filter was involved.
     *
     * This is a merge rule rather than path sensitivity. It cannot say which
     * path runs, only that no single one of them did both things.
     *
     * @param list<Operand> $incoming
     */
    private static function withoutSplitEscapeClaim(
        TaintSet $merged,
        array $incoming,
        TaintState $state,
    ): TaintSet {
        if (! $merged->has(TaintKind::Escaped) || ! $merged->has(TaintKind::EscapeVoided)) {
            return $merged;
        }

        foreach ($incoming as $operand) {
            $taint = $state->effectiveTaintOf($operand);

            if ($taint->has(TaintKind::Escaped) && $taint->has(TaintKind::EscapeVoided)) {
                return $merged;
            }
        }

        return $merged->without(TaintSet::of(TaintKind::Escaped));
    }

    private function transfer(Op $op): bool
    {
        // An expression whose result is the target of an assignment is a write,
        // not a read: `$a['k'] = $v`, `$this->p = $v`, `self::$p = $v` all lower
        // to a fetch followed by an Assign onto the fetch's own result operand.
        // The Assign decides that operand's taint; anything else writing it
        // fights the Assign and the fixed point never settles.
        if (
            $op instanceof Op\Expr
            && ! $op instanceof Op\Expr\Assign
            && ! $op instanceof Op\Expr\AssignRef
            && OperandHelper::isAssignmentTarget($op->result)
        ) {
            return false;
        }

        $calls = $this->resolver->resolveAll($op, $this->context, $this->types);

        if ($calls !== [] && $op instanceof Op\Expr) {
            return $this->transferCalls($op, $calls);
        }

        return match (true) {
            // A parameter's operand is seeded before the first pass (when
            // summarising) and must not be reset by the generic expression
            // branch below, which would wipe the seed on iteration one.
            $op instanceof Op\Expr\Param => false,
            $op instanceof Op\Expr\Closure => $this->transferClosure($op),
            $op instanceof Op\Expr\Assign, $op instanceof Op\Expr\AssignRef => $this->transferAssign($op),
            $op instanceof Op\Expr\ArrayDimFetch => $this->transferArrayDimFetch($op),
            $op instanceof Op\Expr\PropertyFetch => $this->transferPropertyFetch($op),
            $op instanceof Op\Expr\StaticPropertyFetch => $this->transferStaticPropertyFetch($op),
            $op instanceof Op\Expr\ConcatList => $this->transferConcatList($op),
            $op instanceof Op\Expr\BinaryOp\Concat,
            $op instanceof Op\Expr\BinaryOp\Coalesce => $this->transferBinaryConcat($op),
            $op instanceof Op\Expr\BinaryOp => $this->state->set($op->result, TaintSet::empty()),
            $op instanceof Op\Expr\Array_ => $this->transferArrayLiteral($op),
            $op instanceof Op\Expr\Cast\Int_,
            $op instanceof Op\Expr\Cast\Double,
            $op instanceof Op\Expr\Cast\Bool_ => $this->state->set($op->result, TaintSet::empty()),
            $op instanceof Op\Expr\Cast => $this->transferPassThrough(
                $op,
                $op->expr,
                'Cast to a string keeps the value intact.',
            ),
            $op instanceof Op\Iterator\Value => $this->transferIteratorValue($op),
            // Keys, not values: `foreach ( $_GET as $k => $v )` has an
            // attacker-controlled key, but `foreach ( $rows as $k => $v )` after
            // `$rows[$i] = $tainted` does not.
            $op instanceof Op\Iterator\Key => $this->transferPassThrough(
                $op,
                $op->var,
                'Keys of an attacker-controlled collection are attacker-controlled too.',
            ),
            $op instanceof Op\Expr\Assertion => $this->transferAssertion($op),
            $op instanceof Op\Expr\Print_ => $this->transferPrint($op),
            $op instanceof Op\Expr\Eval_ => $this->transferConstructSink($op, 'eval', $op->expr),
            $op instanceof Op\Expr\Include_ => $this->transferInclude($op),
            $op instanceof Op\Terminal\Echo_ => $this->transferEcho($op),
            $op instanceof Op\Terminal\Return_ => $this->transferReturn($op),
            $op instanceof Op\Expr => $this->state->set($op->result, TaintSet::empty()),
            default => false,
        };
    }

    private function transferAssign(Op\Expr\Assign|Op\Expr\AssignRef $op): bool
    {
        if ($op instanceof Op\Expr\AssignRef) {
            // `$a = &$b` is not a copy. From here on the two names are one
            // slot, and a later write through either has to be visible through
            // the other.
            $this->alias($op->var, $op->expr, false);

            // `foreach ( $x as &$v )` lowers to an AssignRef binding `$v` to the
            // iterator's value, so this is where the loop variable gets its
            // name. Link every version of it into the collection.
            foreach ($this->writesBackInto as [$value, $collection]) {
                if ($value === $op->expr) {
                    $this->alias($op->var, $collection, true);
                }
            }
        }

        $value = $op->expr;
        $taint = $this->state->taintOf($value);

        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf('Assigned to %s.', OperandHelper::describe($op->var)),
            [$value],
        );

        // `$a = &$b` binds rather than copies, so it unions like the alias
        // merge does. Setting would undo what the merge added and the two would
        // take turns forever.
        $changed = $op instanceof Op\Expr\AssignRef
            ? $this->state->add($op->var, $taint, $provenance)
            : $this->state->set($op->var, $taint, $provenance);
        $changed = ($op instanceof Op\Expr\AssignRef
            ? $this->state->add($op->result, $taint, $provenance)
            : $this->state->set($op->result, $taint, $provenance)) || $changed;

        // `$a = $b` where `$b` is an array with taint written into its elements
        // has to carry that across, or the taint is lost at the assignment.
        $container = $this->state->containerTaintOf($value);

        if (! $container->isEmpty()) {
            $changed = $this->state->addContainerTaint($op->var, $container, $provenance) || $changed;
            $changed = $this->state->addContainerTaint($op->result, $container, $provenance) || $changed;
        }

        // The per-key slots travel with the array. Without this `$b = $a` would
        // lose the precision and fall back to the whole-array answer.
        $changed = $this->state->copyKeyedTaint($value, $op->var) || $changed;
        $changed = $this->state->copyKeyedTaint($value, $op->result) || $changed;

        return $this->propagateIndirectWrite($op, $taint->union($container)) || $changed;
    }

    /**
     * `$arr['k'] = $v` and `$obj->p = $v` both assign to the *result temporary
     * of a fetch*, not to the base operand, and a later read produces a fresh
     * temporary with no SSA link back. Both therefore need explicit handling.
     */
    private function propagateIndirectWrite(Op\Expr\Assign|Op\Expr\AssignRef $op, TaintSet $taint): bool
    {
        $target = OperandHelper::definingOp($op->var);

        // Record *every* property write, tainted or not. "We watched this
        // property and nothing tainted ever went into it" is the answer the
        // shape rules need, and skipping clean writes meant they could never
        // reach it — so a table name assigned once in a constructor looked
        // exactly like a property the scan had never seen.
        if ($target instanceof Op\Expr\PropertyFetch || $target instanceof Op\Expr\StaticPropertyFetch) {
            $property = OperandHelper::literalString($target->name);

            if ($property !== null) {
                $owner = $target instanceof Op\Expr\PropertyFetch
                    ? $this->propertyOwnerClass($target)
                    : $this->staticOwnerClass($target);

                $this->properties->track($owner, $property);

                // Only when something reached it. A probe run seeds one
                // parameter and no sources at all, so any taint here is the
                // seed, which is exactly the edge a caller needs.
                if (! $taint->isEmpty()) {
                    $this->recordPropertyReference($owner, $property);
                }

                // Whether the written value carried a literal fragment, so a
                // read elsewhere can tell `$this->option_name` holding
                // `'acme_' . $id` from one holding the request verbatim.
                // Recorded on every write, clean ones included: an anchor is a
                // property of the value, not of its taint.
                $this->properties->recordAnchor($owner, $property, $this->anchors->has($op->expr));
            }
        }

        if ($taint->isEmpty()) {
            return false;
        }

        if ($target instanceof Op\Expr\ArrayDimFetch) {
            $key = $target->dim === null ? null : OperandHelper::literalKey($target->dim);

            // A literal key is precise, and a read naming the same key sees
            // only this. `$context['id'] = 42` no longer taints
            // `$context['title']`.
            if ($key !== null) {
                return $this->state->addKeyedTaint(
                    $target->var,
                    $key,
                    $taint,
                    new Provenance(
                        TraceVerb::Propagate,
                        $op,
                        sprintf("Written into %s['%s'].", OperandHelper::describe($target->var), $key),
                        [$op->expr],
                    ),
                );
            }

            // A computed key can land anywhere, so it goes to the whole-array
            // slot — which is what every element write did before.
            //
            // Held apart from the operand's own taint because SSA does not
            // re-version an array for an element write: `$a = array();` and
            // `$a[$k] = $tainted;` write the same operand, and letting them
            // share a slot makes the fixed point oscillate.
            return $this->state->addContainerTaint(
                $target->var,
                $taint,
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf(
                        'Written into %s under a computed key. The key could be any of them, so the whole array '
                            . 'is treated as tainted from here.',
                        OperandHelper::describe($target->var),
                    ),
                    [$op->expr],
                ),
            );
        }

        if ($target instanceof Op\Expr\PropertyFetch || $target instanceof Op\Expr\StaticPropertyFetch) {
            $property = OperandHelper::literalString($target->name);

            if ($property === null) {
                $this->imprecise = true;

                return false;
            }

            $owner = $target instanceof Op\Expr\PropertyFetch
                ? $this->propertyOwnerClass($target)
                : $this->staticOwnerClass($target);

            return $this->properties->add(
                $owner,
                $property,
                $taint,
                $this->writeTrace($op, $property, $taint),
            );
        }

        return false;
    }

    private function transferArrayDimFetch(Op\Expr\ArrayDimFetch $op): bool
    {
        $superglobal = OperandHelper::variableName($op->var);
        $source = $superglobal === null
            ? null
            : $this->registry->source(Matcher::superglobal($superglobal));

        if ($source !== null) {
            return $this->transferSuperglobalFetch($op, $source, $superglobal ?? '');
        }

        $key = $op->dim === null ? null : OperandHelper::literalKey($op->dim);

        if ($this->readsUntaintedSubKey($op, $key)) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        if ($key !== null) {
            return $this->transferKeyedRead($op, $key);
        }

        return $this->transferContainerRead(
            $op,
            $op->var,
            sprintf('Read out of %s.', OperandHelper::describe($op->var)),
        );
    }

    /**
     * `$_FILES['import']['tmp_name']` — a second-level key PHP writes itself.
     *
     * The base has to be the superglobal fetch directly: following it through a
     * variable would need the keyed taint to carry which superglobal it came
     * from, and the two-fetch shape is how every one of the ten plugins that
     * hit this writes it.
     */
    private function readsUntaintedSubKey(Op\Expr\ArrayDimFetch $op, string|int|null $key): bool
    {
        $base = $this->throughAssignments($op->var);

        if (! $base instanceof Op\Expr\ArrayDimFetch) {
            return false;
        }

        $superglobal = OperandHelper::variableName($base->var);

        if ($superglobal === null) {
            return false;
        }

        $source = $this->registry->source(Matcher::superglobal($superglobal));

        return $source !== null && ! $source->matchesSubKey(is_string($key) ? $key : null);
    }

    /**
     * The op that produced a value, seen through any number of plain
     * assignments.
     *
     * `$_FILES['f']['tmp_name']` is one expression and this is the same read
     * spread over two statements:
     *
     *     $csv = $_FILES['subsidy_csv'];
     *     $this->generate_zip( $csv['tmp_name'] );
     *
     * The first version was written against ten corpus plugins that all spell
     * it the first way, and the first real client codebase it was pointed at
     * spelled it the second, which reported `fopen()` on PHP's own upload path
     * as traversal at high severity.
     *
     * Assignments only. Following a phi would mean asking which branch, and a
     * value merged from two places is not one this can speak for.
     */
    private function throughAssignments(Operand $operand): ?Op
    {
        $seen = 0;
        $definition = OperandHelper::definingOp($operand);

        while (
            ($definition instanceof Op\Expr\Assign || $definition instanceof Op\Expr\AssignRef)
            && $seen++ < self::MAX_ASSIGNMENT_HOPS
        ) {
            $definition = OperandHelper::definingOp($definition->expr);
        }

        return $definition;
    }

    /**
     * `$context['title']` — a read that names one constant key.
     *
     * Sees what was written to that key, plus whatever went in under a computed
     * key, because a computed write could have been this one. What it does not
     * see is another key's taint, which is the whole point.
     */
    private function transferKeyedRead(Op\Expr\ArrayDimFetch $op, string|int $key): bool
    {
        $keyed = $this->state->keyedTaintOf($op->var, $key);
        $fallback = $this->state->containerTaintOf($op->var)
            ->union($this->state->taintOf($op->var));
        $taint = $keyed->union($fallback);

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint);
        }

        $provenance = $keyed->isEmpty()
            ? $this->state->containerProvenanceOf($op->var) ?? $this->state->provenanceOf($op->var)
            : $this->state->keyedProvenanceOf($op->var, $key);

        return $this->state->set(
            $op->result,
            $taint,
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf("Read out of %s['%s'].", OperandHelper::describe($op->var), $key),
                [$op->var],
                prefix: $provenance === null ? [] : [],
            ),
        );
    }

    /**
     * A read out of a container: its own taint plus anything written into it
     * through an element.
     */
    /**
     * `foreach ( $items as $item )`, and `foreach ( $items as &$item )`.
     *
     * Reading the collection either way. Bound by reference, the loop variable
     * is also a *write* into the collection — `$item = $_GET['x']` taints
     * `$items` — which the alias pass carries back.
     */
    private function transferIteratorValue(Op\Iterator\Value $op): bool
    {
        if ($op->byRef) {
            $this->writesBackInto[] = [$op->result, $op->var];
        }

        return $this->transferContainerRead(
            $op,
            $op->var,
            'Iterating a tainted collection yields tainted values.',
        );
    }

    private function transferContainerRead(Op\Expr $op, Operand $container, string $description): bool
    {
        // A read out of a container flattens every slot: the value that comes
        // out carries whatever was put in, however it got there. That includes
        // the per-key slots — a computed key could be any of them, and a
        // `foreach` visits all of them.
        $taint = $this->state->effectiveTaintOf($container)
            ->union($this->state->allKeyedTaintOf($container));

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint);
        }

        $provenance = $this->state->taintOf($container)->isEmpty()
            ? $this->state->containerProvenanceOf($container)
            : null;

        return $this->state->set(
            $op->result,
            $taint,
            $provenance ?? new Provenance(TraceVerb::Propagate, $op, $description, [$container]),
        );
    }

    private function transferSuperglobalFetch(Op\Expr\ArrayDimFetch $op, Source $source, string $name): bool
    {
        $key = OperandHelper::literalString($op->dim);

        if (! $source->matchesKey($key)) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        $description = $key === null
            ? sprintf('Tainted by superglobal $%s with a dynamic key.', $name)
            : sprintf("Tainted by superglobal \$%s['%s'].", $name, $key);

        return $this->state->set(
            $op->result,
            $source->kinds,
            new Provenance(TraceVerb::Source, $op, $description),
        );
    }

    private function transferPropertyFetch(Op\Expr\PropertyFetch $op): bool
    {
        $property = OperandHelper::literalString($op->name);

        if ($property === null) {
            $this->imprecise = true;

            return $this->state->set($op->result, TaintSet::empty());
        }

        $owner = $this->propertyOwnerClass($op);

        // A table name or prefix on the database handle is not data. WordPress
        // sets these itself from the install's configuration, and every plugin
        // interpolates them into SQL because there is no other way to name a
        // table.
        //
        // This was implicit until `--include-path` was pointed at core: nothing
        // in a plugin writes `$wpdb->prefix`, so the property carried no taint
        // and the question never arose. Core writes it — `wpdb::get_blog_prefix()`
        // assigns `$this->prefix` — and the moment that body is analysed, the
        // assumption the entire SQL ruleset rests on stops holding. Cookie Law
        // Info gained 23 findings, all rooted at `$wpdb->prefix`.
        if (
            $owner !== null && strtolower($owner) === 'wpdb'
            && in_array($property, $this->registry->safeDatabaseIdentifiers(), true)
        ) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        $stored = $this->properties->get($owner, $property);
        $taint = $stored->union($this->state->taintOf($op->var));

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint);
        }

        return $this->state->set(
            $op->result,
            $taint,
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf('Read from property $%s.', $property),
                [$op->var],
                prefix: $this->properties->originOf($owner, $property),
            ),
        );
    }

    /**
     * `self::$option` and friends. Tracked in the same map as instance
     * properties, keyed by the declaring class.
     */
    private function transferStaticPropertyFetch(Op\Expr\StaticPropertyFetch $op): bool
    {
        $property = OperandHelper::literalString($op->name);

        if ($property === null) {
            $this->imprecise = true;

            return $this->state->set($op->result, TaintSet::empty());
        }

        $owner = $this->staticOwnerClass($op);
        $taint = $this->properties->get($owner, $property);

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint);
        }

        return $this->state->set(
            $op->result,
            $taint,
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf('Read from static property $%s.', $property),
                prefix: $this->properties->originOf($owner, $property),
            ),
        );
    }

    /**
     * The trace of a property write, recorded so that a read elsewhere can show
     * where the value came from.
     *
     * @return list<TraceStep>
     */
    private function writeTrace(Op\Expr\Assign|Op\Expr\AssignRef $op, string $property, TaintSet $taint): array
    {
        // Summary extraction seeds a parameter with every taint kind, which is
        // a hypothesis rather than a flow. A trace built from it starts at
        // "parameter 0, assumed tainted while summarising" — meaningless in a
        // reported finding, and it was leaking into them through the property
        // map. Only real runs record origins.
        if ($this->seedParameterIndex !== null) {
            return [];
        }

        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null) {
            return [];
        }

        $step = $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            sprintf('Written to property $%s.', $property),
        );

        return $this->traces->build($op->expr, $kind, $step);
    }

    private function staticOwnerClass(Op\Expr\StaticPropertyFetch $fetch): ?string
    {
        $class = OperandHelper::literalString($fetch->class);

        if ($class === null || in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
            return $this->context->className;
        }

        return $class;
    }

    /**
     * Which class a property belongs to.
     *
     * Through the same resolver the call machinery uses, so the property map
     * and the call graph cannot disagree about what a receiver is. That matters
     * more than it sounds: an unknown owner lands in a single `?::name` bucket
     * shared by every untyped receiver in the scan, and `$wpdb->comments` — a
     * table name — was colliding there with `WP_Query::$comments`, which holds
     * actual comment data. Under `--include-path` at WordPress core the
     * collision produced a fourteen-step trace to
     * `OPTIMIZE TABLE {$wpdb->comments}`.
     */
    private function propertyOwnerClass(Op\Expr\PropertyFetch $fetch): ?string
    {
        return $this->receivers->classOf($fetch->var, $this->context, $this->types);
    }

    private function transferConcatList(Op\Expr\ConcatList $op): bool
    {
        $parts = [];

        foreach ($op->list as $item) {
            if ($item instanceof Operand) {
                $parts[] = $item;
            }
        }

        return $this->transferUnion(
            $op,
            $parts,
            'Interpolated into a string. Interpolation concatenates; it does not escape.',
        );
    }

    private function transferBinaryConcat(Op\Expr\BinaryOp $op): bool
    {
        $description = $op instanceof Op\Expr\BinaryOp\Coalesce
            ? 'Null coalescing passes the left-hand value through when it is set.'
            : 'Concatenated into a larger string.';

        return $this->transferUnion($op, [$op->left, $op->right], $description);
    }

    /**
     * An array literal's *keys* go into the operand's own taint and its
     * *values* into the container slot.
     *
     * Everything that reads an array reads both, so this changes nothing
     * downstream — except for the two things that read keys alone. Without the
     * split, `array_keys( array( 'hook' => $tainted ) )` came back tainted, and
     * WooCommerce interpolates exactly that into fourteen prepared queries.
     */
    private function transferArrayLiteral(Op\Expr\Array_ $op): bool
    {
        $keys = [];
        $values = [];

        foreach ($op->keys as $item) {
            if ($item instanceof Operand) {
                $keys[] = $item;
            }
        }

        foreach ($op->values as $item) {
            if ($item instanceof Operand) {
                $values[] = $item;
            }
        }

        $changed = $this->transferUnion($op, $keys, 'Used as a key in an array literal.');

        // Pair each value with its key, so `array( 'title' => $_GET['t'], 'id' => 7 )`
        // taints one slot rather than the whole array. This is the commoner
        // construction of the two — a literal is how most tainted arrays are
        // built, and an element write is how they are amended.
        $unkeyed = [];

        foreach ($values as $index => $value) {
            $taint = $this->state->effectiveTaintOf($value);

            if ($taint->isEmpty()) {
                continue;
            }

            $key = isset($op->keys[$index]) && $op->keys[$index] instanceof Operand
                ? OperandHelper::literalKey($op->keys[$index])
                : null;

            if ($key === null) {
                // A computed key, or a list with no keys at all: the value
                // could be at any index, so it goes to the whole-array slot.
                $unkeyed[] = $value;

                continue;
            }

            $changed = $this->state->addKeyedTaint(
                $op->result,
                $key,
                $taint,
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf("Placed into an array literal under '%s'.", $key),
                    [$value],
                ),
            ) || $changed;
        }

        $valueTaint = $this->state->unionOf($unkeyed);

        if ($valueTaint->isEmpty()) {
            return $changed;
        }

        return $this->state->addContainerTaint(
            $op->result,
            $valueTaint,
            new Provenance(TraceVerb::Propagate, $op, 'Placed into an array literal.', $unkeyed),
        ) || $changed;
    }

    /**
     * Propagate the union of several operands into an expression's result,
     * keeping the two taint slots apart.
     *
     * Own taint flows to own, element taint flows to element. Folding element
     * taint into the own slot is what made `is_callable( array( $a, $b ) )`
     * oscillate: `Op\Expr\Array_` set the own slot from the keys alone while
     * the assertion over it set the same slot from the union, and the two
     * disagreed forever.
     *
     * @param list<Operand> $inputs
     */
    private function transferUnion(Op\Expr $op, array $inputs, string $description): bool
    {
        $taint = $this->state->unionOfOwn($inputs);
        $container = $this->state->unionOfContainers($inputs);

        $provenance = $taint->isEmpty() && $container->isEmpty()
            ? null
            : new Provenance(TraceVerb::Propagate, $op, $description, $inputs);

        $changed = $this->writeResult($op->result, $taint, $provenance);

        if ($container->isEmpty() || $provenance === null) {
            return $changed;
        }

        return $this->state->addContainerTaint($op->result, $container, $provenance) || $changed;
    }

    /**
     * A branch condition that proved something about the value.
     *
     * `if ( ! is_int( $id ) ) { return; }` leaves `$id` an int on the way out,
     * and an int carries no payload. php-cfg gives that branch its own operand,
     * so the two paths are already separable without per-block state — see
     * {@see AssertionNarrowing} for why this is safe and where it is not.
     *
     * Everything else passes through. `isset($x)` and `!empty($x)` narrow a
     * type without escaping anything, and their assertion reuses the operand
     * the value was written to, which is the shape that oscillates.
     */
    private function transferAssertion(Op\Expr\Assertion $op): bool
    {
        // Someone else already writes this operand, so writing it here makes
        // two ops disagree about one value and the fixed point never settles.
        //
        //     if ( isset( $GLOBALS['post'] ) && $GLOBALS['post'] instanceof WP_Post ) {
        //
        // php-cfg gives the assertion the *same result operand* the array read
        // produces. The read said `(none)`, the assertion passed
        // `escape_voided` through, and the two took turns for all 64 iterations
        // — one function in a real theme, found by naming it in the warning.
        //
        // Doing nothing leaves the value to the op that genuinely produces it,
        // which is the answer a pass-through would have copied anyway. For the
        // narrowing branch it costs the narrowing, which can only keep taint
        // that would otherwise be cleared — the safe direction, and not a
        // direction the path-sensitivity fixtures travel: those get a fresh
        // operand per branch, with the assertion as its only writer.
        if (OperandHelper::isWrittenElsewhere($op->result, $op)) {
            return false;
        }

        if (! AssertionNarrowing::narrows($op)) {
            return $this->transferPassThrough(
                $op,
                $op->expr,
                'An isset() or empty() guard narrows the type but does not escape the value.',
            );
        }

        return $this->writeResult(
            $op->result,
            TaintSet::empty(),
            new Provenance(
                TraceVerb::Sanitize,
                $op,
                'A guard proved this is a number on this path, and a number carries no payload.',
                [$op->expr],
            ),
        );
    }

    /**
     * `function () use ( $raw )` — what the closure captured, published for it.
     *
     * The body is a separate function with its own context, and the captured
     * variable arrives inside it as a free operand: a Temporary written by an
     * entry Phi with nothing flowing in. Nothing connected the two, so this was
     * silent, in both the shape WordPress writes constantly and the plain one:
     *
     *     $raw = $_GET['msg'];
     *     add_action( 'wp_footer', function () use ( $raw ) {
     *         echo $raw;
     *     } );
     *
     * A capture is the same shape as an include's scope — a map of names to
     * taint, published by one site and read by another, converging in the
     * interprocedural loop — so it uses the same table rather than a second one.
     *
     * By value, not by reference: `use ( &$raw )` also writes back out, which is
     * not modelled, so a closure that taints a captured variable by reference is
     * still missed.
     */
    private function transferClosure(Op\Expr\Closure $op): bool
    {
        // A probe run seeds one parameter with every taint kind to find out what
        // the function does with it. Publishing that into a table the whole scan
        // shares makes the seed an assertion, which is the same mistake the
        // property map made and the same fix: the baseline run, which seeds
        // nothing and reads the body as written, is the one that publishes.
        if ($this->seedParameterIndex !== null) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        $scope = [];
        $origins = [];
        $key = FunctionContext::keyFor($op->func, $this->context->file);

        // By name, not by operand. php-cfg gives the use clause its own fresh
        // `Variable` nodes rather than the SSA temporaries holding the values,
        // so asking those operands what they carry answers "nothing" every time.
        $enclosing = $this->namedScopeWithOrigins();

        foreach ($op->useVars as $captured) {
            if (! $captured instanceof Operand) {
                continue;
            }

            $name = OperandHelper::variableName($captured);

            if ($name === null || ! isset($enclosing['taint'][$name])) {
                continue;
            }

            $scope[$name] = $enclosing['taint'][$name];

            if (isset($enclosing['origins'][$name])) {
                $origins[$name] = $enclosing['origins'][$name];
            }
        }

        $changed = $scope === [] ? false : $this->scopes->addInto($key, $scope, $origins);

        // The closure value itself is a callable, not the captured data.
        return $this->state->set($op->result, TaintSet::empty()) || $changed;
    }

    private function transferPassThrough(Op\Expr $op, Operand $input, string $description): bool
    {
        return $this->transferUnion($op, [$input], $description);
    }

    private function transferReturn(Op\Terminal\Return_ $op): bool
    {
        if ($op->expr === null) {
            return false;
        }

        // AND across returns: one path that returns the request verbatim is
        // enough to make the function useless as an anchor. Not part of the
        // fixed point — it is a property of the syntax, so it cannot oscillate.
        $anchored = $this->anchors->hasWithinBody($op->expr);
        $this->returnAnchored = $this->returnAnchored === null
            ? $anchored
            : ($this->returnAnchored && $anchored);

        // A guard can prove the value safe on the path that returns it, not
        // only on the path to a sink. Core's `wp_specialchars()` opens with
        //
        //     if ( ! preg_match( '/[&<>"\']/', $string ) ) { return $string; }
        //
        // and every plugin vendoring a copy of it handed us a false positive,
        // because the early return carried the argument's taint out untouched.
        $taint = $this->guards->isGuarded($op->expr, $this->currentBlock)
            ? TaintSet::empty()
            : $this->state->taintOf($op->expr);

        $this->reportShortcodeReturn($op, $op->expr, $taint);

        $merged = $this->returnTaint->union($taint);
        $changed = ! $merged->equals($this->returnTaint);
        $this->returnTaint = $merged;

        return $changed;
    }

    /**
     * What a shortcode or block render callback returns is printed by WordPress.
     *
     *     add_shortcode( 'badge', 'acme_badge' );
     *     function acme_badge( $atts ) {
     *         return '<span style="color:' . $atts['color'] . '">x</span>';
     *     }
     *
     * There is no `echo` to find. `do_shortcode()` prints the return value, and
     * the call that reaches it is core's, not the plugin's, so a rule looking
     * for output constructs sees nothing and the callback reads as clean.
     *
     * The escaped form is unaffected: the return has to carry `html` to report,
     * so `return '<span>' . esc_attr( $atts['color'] ) . '</span>'` stays quiet.
     */
    private function reportShortcodeReturn(Op\Terminal\Return_ $op, Operand $operand, TaintSet $taint): void
    {
        $kind = $this->printedReturns[$this->context->key] ?? null;

        if (
            $kind === null
            || ! $this->collecting
            || ! $this->collectFindings
            || ! $taint->has(TaintKind::Html)
        ) {
            return;
        }

        $this->emit(
            'wp.xss.unescaped-output',
            TaintKind::Html,
            Severity::High,
            $op,
            $kind . ' return',
            $operand,
            sprintf(
                'Returned from a %s, which WordPress prints. Escape it here: there is no later point at '
                    . 'which it can be escaped.',
                $kind,
            ),
        );
    }

    private function transferEcho(Op\Terminal\Echo_ $op): bool
    {
        $this->checkConstructSink($op, 'echo', $op->expr);

        return false;
    }

    private function transferPrint(Op\Expr\Print_ $op): bool
    {
        $this->checkConstructSink($op, 'print', $op->expr);

        return $this->state->set($op->result, TaintSet::empty());
    }

    private function transferInclude(Op\Expr\Include_ $op): bool
    {
        $construct = match ($op->type) {
            Op\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Op\Expr\Include_::TYPE_REQUIRE => 'require',
            Op\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
            default => 'include',
        };

        $this->checkConstructSink($op, $construct, $op->expr);

        // An include's *result* is whatever the file returned, which we cannot
        // know. Its scope, on the other hand, we can.
        return $this->joinIncludedScope($op) || $this->state->set($op->result, TaintSet::empty());
    }

    private function transferConstructSink(Op\Expr $op, string $construct, Operand $operand): bool
    {
        $this->checkConstructSink($op, $construct, $operand);

        return $this->state->set($op->result, TaintSet::empty());
    }

    private function checkConstructSink(Op $op, string $construct, Operand $operand): void
    {
        foreach ($this->registry->sinksFor(Matcher::construct($construct)) as $sink) {
            $this->reportSink($sink, $op, $operand, $construct);
        }
    }

    // -------------------------------------------------------------------
    // Calls
    // -------------------------------------------------------------------

    /**
     * One call op, one or more callees.
     *
     * `call_user_func( $cb, $x )` where `$cb` holds a different name on each
     * side of a branch reaches both, and picking one would be a guess. Every
     * callee is analysed and the effects are unioned, so a sink in either is
     * reported and the return value carries what either could produce.
     *
     * The union is what makes this safe to iterate: writes accumulate rather
     * than replace while several callees are in play, so the order they are
     * visited in cannot change the answer.
     *
     * @param list<CallTarget> $calls
     */
    private function transferCalls(Op\Expr $op, array $calls): bool
    {
        if (count($calls) === 1 && $calls[0]->resultMode === CallResultMode::Value) {
            return $this->transferCall($op, $calls[0]);
        }

        $previousUnion = $this->unionResultWrites;
        $previousMode = $this->resultMode;
        $this->unionResultWrites = true;
        $changed = false;

        try {
            foreach ($calls as $call) {
                $this->resultMode = $call->resultMode;
                $changed = $this->transferCall($op, $call) || $changed;
            }
        } finally {
            $this->unionResultWrites = $previousUnion;
            $this->resultMode = $previousMode;
        }

        return $changed;
    }

    /**
     * Write a call's result, unioning when several callees share the operand.
     *
     * With one callee this is a plain assignment, and a callee that returns
     * clean clears whatever a previous iteration left. With several, replacing
     * would mean the last one visited won.
     */
    /**
     * A non-convergence diagnostic: the operands that would not settle, and the
     * ops that write each of them.
     *
     * The oscillator is the operand whose value changed far more than any
     * other — two writers disagreeing — so naming it and its writers turns
     * "results may be incomplete" into a line that points at the cause.
     */
    private function describeOscillation(int $iterations): string
    {
        $lines = [sprintf(
            '%s did not converge in %d iterations.',
            $this->context->displayName,
            $iterations,
        )];

        foreach (array_slice($this->state->oscillators($iterations - 1), 0, 3) as $entry) {
            $operand = $entry['operand'];
            $writers = [];

            foreach ($operand->ops as $writer) {
                if ($writer instanceof Op) {
                    $pos = OperandHelper::position($writer, $this->context->file->sourceMap);
                    $writers[] = sprintf(
                        '%s at %s:%d',
                        (new \ReflectionClass($writer))->getShortName(),
                        $this->context->file->relativePath,
                        $pos['line'],
                    );
                }
            }

            $lines[] = sprintf(
                '  %s changed %d times, written by: %s',
                OperandHelper::describe($operand),
                $entry['changes'],
                $writers === [] ? '(unknown)' : implode('; ', $writers),
            );
        }

        return implode("\n", $lines);
    }

    private function writeResult(Operand $result, TaintSet $taint, ?Provenance $provenance = null): bool
    {
        $voided = $this->voidEscaping($taint);

        // Say where. A step describing the propagation is the wrong answer to
        // "filtered where?", and it was the only one in the trace.
        if (! $voided->equals($taint)) {
            $provenance = $this->voidProvenance($voided) ?? $provenance;
        }

        $taint = $voided;

        // The callee's return is not what this call evaluates to. It was still
        // analysed, which is the point: its sinks fired.
        if ($this->resultMode === CallResultMode::Discard) {
            return false;
        }

        if ($this->resultMode === CallResultMode::Container) {
            return $taint->isEmpty() || $provenance === null
                ? false
                : $this->state->addContainerTaint($result, $taint, $provenance);
        }

        if (! $this->unionResultWrites) {
            return $this->state->set($result, $taint, $provenance);
        }

        return $taint->isEmpty()
            ? false
            : $this->state->add($result, $taint, $provenance);
    }

    private function transferCall(Op\Expr $op, CallTarget $call): bool
    {
        if ($call->dynamic) {
            return $this->transferDynamicCall($op, $call);
        }

        $matcher = $call->matcher;

        // Applied before the role dispatch and folded into the result, because
        // a call can write back through an argument *and* be a sanitizer,
        // propagator or sink in its own right. Every branch below returns.
        // Anything a third party can hook stands between the escaper and the
        // sink, so whatever guarantee the escaper gave does not survive it.
        // That is `apply_filters()` itself, and equally the 524 core functions
        // that run a filter and return the result — `get_the_title()` looks
        // like an accessor and is a filter in a coat.
        $this->voidingCall = $matcher !== null && $this->voidsEscaping($matcher, $call) ? $call : null;
        $this->voidingOp = $this->voidingCall === null ? null : $op;

        $changed = $matcher === null ? false : $this->applyByRefEffect($op, $call, $matcher);
        $changed = ($matcher === null ? false : $this->joinTemplateScope($op, $call, $matcher)) || $changed;

        if ($matcher !== null) {
            $sinks = $this->registry->sinksFor($matcher);

            foreach ($sinks as $sink) {
                $this->reportCallSink($sink, $op, $call, $matcher);
            }

            $sanitizer = $this->registry->sanitizer($matcher);

            if ($sanitizer !== null) {
                return $this->transferSanitizer($op, $call, $sanitizer, $matcher) || $changed;
            }

            $source = $this->registry->source($matcher);

            if ($source !== null && $this->sourceApplies($source, $call)) {
                return $this->writeResult(
                    $op->result,
                    $source->kinds,
                    new Provenance(
                        TraceVerb::Source,
                        $op,
                        sprintf(
                            '%s returns %s data.',
                            $matcher->describe(),
                            $source->stored ? 'stored, user-supplied' : 'user-supplied',
                        ),
                    ),
                ) || $changed;
            }

            $propagator = $this->registry->propagator($matcher);

            if ($propagator !== null) {
                return $this->transferPropagator($op, $call, $propagator->arguments, $matcher, $propagator->note)
                    || $changed;
            }

            if ($this->registry->isSafeCall($matcher)) {
                return $this->writeResult($op->result, TaintSet::empty()) || $changed;
            }

            if ($sinks !== []) {
                // A sink with no other role consumes the value; whatever it
                // returns is not derived from the tainted argument in a way we
                // model.
                return $this->writeResult($op->result, TaintSet::empty()) || $changed;
            }
        }

        if ($this->options->interprocedural && $call->userFunctionKey !== null) {
            return $this->transferUserCall($op, $call) || $changed;
        }

        if ($call->userFunctionKey !== null) {
            // --no-interprocedural: user calls are opaque, which is exactly the
            // Phase 3 behaviour this flag exists to reproduce.
            return $this->writeResult($op->result, TaintSet::empty()) || $changed;
        }

        // A named function the catalogue has no model for. Returning clean is
        // the deliberate choice: a documented false negative beats an
        // undocumented false positive.
        return $this->writeResult($op->result, TaintSet::empty()) || $changed;
    }

    /**
     * A call that writes back through one of its arguments.
     *
     * `preg_match( $re, $subject, $matches )` leaves the caller holding an array
     * built from `$subject`, and SSA does not give that write its own operand —
     * the argument the caller passed in *is* the slot. So this adds rather than
     * sets: two ops share a slot, and only growing keeps the fixed point
     * monotone.
     */
    private function applyByRefEffect(Op\Expr $op, CallTarget $call, Matcher $matcher): bool
    {
        $effect = $this->registry->byRefEffect($matcher);

        if ($effect === null) {
            return false;
        }

        $target = $call->argument($effect->writes);

        if ($target === null) {
            return false;
        }

        $sources = [];

        foreach ($effect->from as $index) {
            $argument = $call->argument($index);

            if ($argument !== null) {
                $sources[] = $argument;
            }
        }

        $taint = $this->state->unionOf($sources);

        if ($taint->isEmpty()) {
            return false;
        }

        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf(
                '%s writes through argument %d, which carries %s out to the caller.',
                $matcher->describe(),
                $effect->writes + 1,
                $taint->describe(),
            ),
            $sources,
        );

        return $effect->asContainer
            ? $this->state->addContainerTaint($target, $taint, $provenance)
            : $this->state->add($target, $taint, $provenance);
    }

    /**
     * `get_template_part()`: hand the template its `$args`, and nothing else.
     *
     * Deliberately not the include join. A template loaded this way runs inside
     * `load_template()`, so it sees the globals and the `$args` array — never
     * the caller's locals. Sharing the caller's whole scope would connect every
     * variable in a theme's `index.php` to every partial it renders, which is
     * over-approximation in exactly the files a theme puts its output in.
     */
    private function joinTemplateScope(Op\Expr $op, CallTarget $call, Matcher $matcher): bool
    {
        if ($this->includes === null) {
            return false;
        }

        $loader = $this->registry->templateLoader($matcher);

        if ($loader === null) {
            return false;
        }

        $site = IncludeGraph::templateSiteKey(
            $this->context->file->relativePath,
            $op->getLine(),
            $this->templateOffset++,
        );

        $targets = $this->includes->targetsFor($site);

        if ($targets === []) {
            $this->imprecise = true;

            return false;
        }

        $args = $loader->argsArgument === null ? null : $call->argument($loader->argsArgument);
        $scope = [];
        $origins = [];
        $keyed = [];

        if ($args !== null) {
            $taint = $this->state->effectiveTaintOf($args)
                ->union($this->state->allKeyedTaintOf($args));

            if (! $taint->isEmpty()) {
                $scope['args'] = $taint;
                $origin = $this->scopeTrace($op, $args, 'args', $taint);

                if ($origin !== []) {
                    $origins['args'] = $origin;
                }

                // The keys travel too, so a template reading `$args['id']` is
                // no more a finding than reading `$context['id']` in the file
                // that built the array.
                $keyed['args'] = $this->state->keyedTaintMapOf($args);
            }
        }

        $changed = false;

        foreach ($targets as $target) {
            $key = strtolower($target . '::{main}');
            $changed = $this->scopes->addInto($key, $scope, $origins, $keyed) || $changed;
        }

        return $changed;
    }

    private function sourceApplies(Source $source, CallTarget $call): bool
    {
        if ($source->appliesBy === Source::ADD_QUERY_ARG_BASE && ! self::addQueryArgReadsRequestUri($call)) {
            return false;
        }

        if ($source->argumentLiteralContains === null) {
            return true;
        }

        $argument = $call->argument($source->argumentIndex);
        $literal = $argument === null ? null : OperandHelper::literalString($argument);

        return $literal !== null && str_contains($literal, $source->argumentLiteralContains);
    }

    private function transferSanitizer(
        Op\Expr $op,
        CallTarget $call,
        Sanitizer $sanitizer,
        Matcher $matcher,
    ): bool {
        $incoming = $this->state->unionOf($call->arguments);

        if ($sanitizer->requiresLiteralArgument !== null) {
            $formatArgument = $call->argument($sanitizer->requiresLiteralArgument);

            if ($formatArgument !== null && $this->formatStringIsUnsafe($formatArgument)) {
                return $this->reportNonLiteralSanitizer($op, $call, $sanitizer, $matcher, $formatArgument, $incoming);
            }
        }

        if ($sanitizer->imprecise) {
            $this->imprecise = true;
        }

        $cleared = $sanitizer->clearsBy === null
            ? $sanitizer->apply($incoming)
            : $incoming->without($this->strategyClears($sanitizer, $call));

        // Applying any sanitizer settles two questions whatever else it did or
        // did not clear: where the value came from, and whether anyone cleaned
        // it before storing it. Propagators settle neither, which is what keeps
        // `trim()` and `wp_unslash()` from passing for sanitisers.
        $cleared = $cleared->without(TaintSet::of(TaintKind::Unknown, TaintKind::Storage));

        // A quote-escaper does not remove the danger, it moves it: the value is
        // safe between quotes and no safer than before without them. Trading
        // `sql` for `sql_unquoted` is what lets the sink tell those apart, and
        // what keeps a table name from a helper — which never carried `sql` —
        // out of it entirely.
        if ($sanitizer->quotedOnly && $incoming->has(TaintKind::Sql)) {
            $cleared = $cleared->union(TaintSet::of(TaintKind::SqlUnquoted));
        }

        // Remember that this value has been escaped, so that a filter standing
        // between here and the echo can be seen to have voided it — and clear
        // any earlier voiding, because escaping *after* the filter is the
        // correct order and the whole point of the rule.
        //
        //     echo wp_kses_post( apply_filters( 'x', esc_html( $v ) ) );
        //
        // is safe: the filter can return anything it likes and wp_kses_post()
        // still runs on the result. Without this the rule reported it, which is
        // telling people the right answer is wrong.
        // Only an output escaper marks a value escaped. absint() and intval()
        // clear everything, but coercing an id to an integer is not escaping
        // content — and treating it as such made `echo get_the_title( absint(
        // $_GET['id'] ) )` look like escaping voided by a filter, because the
        // id carried the marker into a call whose result has nothing to do
        // with it.
        //
        // Escaping a literal marks nothing. `esc_html__( 'Enter a name for this
        // tax rate.', 'woocommerce' )` is a fixed English sentence before the
        // call and the same sentence after it, so a filter downstream has no
        // escaping to void. WooCommerce's admin templates escape literals and
        // hand them to `wc_help_tip()`, and were the largest single reporter of
        // this rule.
        //
        // The attack the rule describes needs a value an attacker can reach.
        // Without one the claim collapses into "an unescaped apply_filters()
        // was echoed", which is a different rule with a different answer.
        //
        // The test is the argument's shape, not its taint: a function parameter
        // carries no taint either, and `function render( $value ) { echo
        // apply_filters( 'x', esc_html( $value ) ); }` is the exact case this
        // rule exists for.
        if (
            $sanitizer->clears->has(TaintKind::Html)
            && ! $sanitizer->clearsEverything
            && ! $this->escapesOnlyLiterals($call, $sanitizer)
        ) {
            $cleared = $cleared
                ->without(TaintSet::of(TaintKind::EscapeVoided))
                ->union(TaintSet::of(TaintKind::Escaped));
        }

        if ($cleared->isEmpty()) {
            return $this->writeResult($op->result, $cleared);
        }

        return $this->writeResult(
            $op->result,
            $cleared,
            new Provenance(
                TraceVerb::Sanitize,
                $op,
                sprintf(
                    '%s clears %s. Still carrying: %s.',
                    $matcher->describe(),
                    $sanitizer->describeClears(),
                    $cleared->describe(),
                ),
                $call->arguments,
                imprecise: $sanitizer->imprecise,
            ),
        );
    }

    /**
     * Write the caller's taint into the properties the callee assigns it to.
     *
     * The counterpart to {@see reportSummarySinks}: that one reports a sink the
     * argument reaches inside the callee, this one records a property it lands
     * in. Both exist because a probe run cannot commit anything itself — its
     * parameter carries a seed rather than a value, and a seed written into the
     * shared map becomes an assertion nobody made.
     *
     *     $log = new Logger( $_GET['f'] );   // Logger::$file gets path taint
     *     $log->write();                      //   → reported, from the real flow
     *
     * A sealed map makes this a no-op, which is what keeps the caller's own
     * probe runs from reintroducing the problem one frame up.
     */
    private function applySummaryProperties(
        Op\Expr $op,
        FunctionSummary $summary,
        int $index,
        Operand $argument,
        TaintSet $argumentTaint,
    ): bool {
        $changed = false;

        foreach ($summary->propertiesFor($index) as [$class, $property]) {
            $changed = $this->properties->add(
                $class,
                $property,
                $argumentTaint,
                $this->propertyWriteTrace($op, $argument, $argumentTaint, $summary, $property),
            ) || $changed;

            // The anchor is the caller's to settle. Inside the callee the value
            // is a parameter, and an unknown parameter reads as anchored — so a
            // constructor storing `$name` on a property recorded the property
            // as anchored whatever the caller passed. Recording the argument's
            // own anchor state closes that: `new Setting( 'acme_' . $x )` pens
            // the option name in, `new Setting( $_POST['name'] )` does not, and
            // AND-ing keeps one unanchored write decisive.
            $this->properties->recordAnchor($class, $property, $this->anchors->has($argument));
        }

        return $changed;
    }

    /**
     * The trace of a property write that happened inside a callee.
     *
     * @return list<TraceStep>
     */
    private function propertyWriteTrace(
        Op\Expr $op,
        Operand $argument,
        TaintSet $taint,
        FunctionSummary $summary,
        string $property,
    ): array {
        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null || $this->seedParameterIndex !== null) {
            return [];
        }

        return $this->traces->build($argument, $kind, $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            sprintf('Passed to %s(), which writes it into $%s.', $summary->displayName, $property),
        ));
    }

    /**
     * Drop an escape-voided claim a callee cannot substantiate at this site.
     *
     * WooCommerce's `wc_help_tip()` escapes and then hands the result to a
     * filter, which is the shape this rule exists to find:
     *
     *     return apply_filters(
     *         'wc_help_tip',
     *         '<span … aria-label="' . esc_attr( $aria_label ) . '" …></span>',
     *         $sanitized_tip, $tip, $allow_html
     *     );
     *
     * A summary records that as introduced — produced whatever the arguments
     * were — so every one of the 65 call sites in WooCommerce's status report
     * inherited it, each passing a fixed English sentence.
     *
     * The markers are a claim about a value, and when nothing tainted was
     * handed in they have no value to be about. A callee that reaches a source
     * on its own introduces that source's kind alongside them, so this only
     * ever discards a pair standing by itself.
     */
    private static function withoutUnearnedEscapeMarkers(TaintSet $result, bool $anyArgumentTainted): TaintSet
    {
        if ($anyArgumentTainted) {
            return $result;
        }

        $markers = TaintSet::of(TaintKind::Escaped, TaintKind::EscapeVoided);

        return $result->without($markers)->isEmpty() ? TaintSet::empty() : $result;
    }

    /**
     * Is every value this escaper was handed a compile-time constant?
     *
     * A literal has no attacker anywhere in its history, so escaping it proves
     * nothing and a later filter voids nothing. Anything else — a parameter, a
     * property, another call's return — could carry a payload, and does not
     * have to be visibly tainted for the rule to apply.
     */
    private function escapesOnlyLiterals(CallTarget $call, Sanitizer $sanitizer): bool
    {
        $indices = $sanitizer->arguments->resolve($call->argumentCount());

        if ($indices === []) {
            return false;
        }

        foreach ($indices as $index) {
            if (! $call->argument($index) instanceof Operand\Literal) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a `prepare()` format string is one prepare() cannot protect.
     *
     * "Not a string literal" is not the same as "unsafe", and treating it as
     * such produced 532 critical findings on the corpus, almost all of them on
     * this shape:
     *
     * ```php
     * $table = self::table();   // returns $wpdb->prefix . 'wfconfig'
     * $wpdb->get_row( $wpdb->prepare( "SELECT … FROM {$table} WHERE name = %s", $key ) );
     * ```
     *
     * The format string is not literal, and it is also not dangerous: every
     * character of it is accounted for. The question prepare() actually needs
     * answering is whether anything attacker-controlled reached the format
     * string, which is the same question the query-shape rule asks, so it uses
     * the same machinery.
     */
    /**
     * Whether `add_query_arg()` reads the current request at this call site.
     *
     * It reads `$_SERVER['REQUEST_URI']` only when no base URI was handed to
     * it, and where the base would sit depends on the shape of the first
     * argument:
     *
     * ```php
     * add_query_arg( [ 'a' => 1 ] );                  // reads REQUEST_URI
     * add_query_arg( [ 'a' => 1 ], $endpoint );       // does not
     * add_query_arg( 'a', 1 );                        // reads REQUEST_URI
     * add_query_arg( 'a', 1, $endpoint );             // does not
     * ```
     *
     * Modelling it as an unconditional source produced SSRF findings on every
     * plugin that builds a third-party API URL this way — Contact Form 7 calls
     * it with the Sendinblue endpoint and got two. Modelling it as never a
     * source would lose reflected XSS through the current URL, which is a real
     * and common bug.
     */
    private static function addQueryArgReadsRequestUri(CallTarget $call): bool
    {
        $first = $call->argument(0);

        // The key form is the one whose first argument is a literal string;
        // everything else is taken to be the array form. Checking for a literal
        // `array()` instead was too narrow — Cookie Law Info passes
        // `$this->get_args`, a property holding an array, and got three SSRF
        // findings for it.
        //
        // The cost is `add_query_arg( $key, $value )` with a computed key,
        // which is read as the array form and stays quiet. That is the rarer
        // shape, and quiet is the direction to fail in on a call this
        // ambiguous.
        $baseIndex = $first !== null && OperandHelper::literalString($first) !== null ? 2 : 1;

        return $call->argumentCount() <= $baseIndex;
    }

    /**
     * What a strategy-driven sanitizer clears at this particular call site.
     *
     * Nothing, when it cannot tell — which leaves the incoming taint untouched
     * and makes the call behave exactly like the propagator it would otherwise
     * be. That is the right failure: `preg_replace()` with a computed pattern
     * proves nothing, and pretending otherwise would launder real taint.
     */
    private function strategyClears(Sanitizer $sanitizer, CallTarget $call): TaintSet
    {
        if ($sanitizer->clearsBy !== Sanitizer::ALLOWLIST_PATTERN) {
            return TaintSet::empty();
        }

        $pattern = $call->argument($sanitizer->patternArgument);
        $replacement = $call->argument($sanitizer->replacementArgument);

        $patternLiteral = $pattern === null ? null : OperandHelper::literalString($pattern);
        $replacementLiteral = $replacement === null ? null : OperandHelper::literalString($replacement);

        if ($patternLiteral === null || $replacementLiteral === null) {
            return TaintSet::empty();
        }

        return AllowlistPattern::clears($patternLiteral, $replacementLiteral) ?? TaintSet::empty();
    }

    private function formatStringIsUnsafe(Operand $formatArgument): bool
    {
        if ($this->literals->isEffectivelyLiteral($formatArgument)) {
            return false;
        }

        // A proven flow from a source: unambiguously unsafe.
        if ($this->state->taintOf($formatArgument)->has(TaintKind::Sql)) {
            return true;
        }

        // No proven flow, but something in it the engine cannot account for.
        return $this->queryShapes->unaccountedComponent($formatArgument, $this->context, $this->types) !== null;
    }

    /**
     * `$wpdb->prepare()` with a format string built from a variable.
     *
     * prepare() provides no protection at all in this shape, so the call is
     * reported and the taint is passed through rather than cleared.
     */
    private function reportNonLiteralSanitizer(
        Op\Expr $op,
        CallTarget $call,
        Sanitizer $sanitizer,
        Matcher $matcher,
        Operand $formatArgument,
        TaintSet $incoming,
    ): bool {
        $ruleId = $sanitizer->literalViolationRuleId;

        if ($ruleId !== null && $this->collecting) {
            $kind = $sanitizer->clears->kinds()[0] ?? TaintKind::Sql;

            // Severity follows the evidence, the way the query-shape rule
            // already does it. A proven flow from a source is exploitable; a
            // format string the engine merely could not account for is a "look
            // at this". 187 of the corpus's 205 findings on this rule were the
            // second kind and every one was reported critical, which is 187 of
            // the 352 criticals a first run put in front of someone.
            $proven = $this->state->taintOf($formatArgument)->has(TaintKind::Sql);

            $this->emit(
                $ruleId,
                $kind,
                $this->registry->severityForRule(
                    $ruleId,
                    $proven ? Severity::Critical : Severity::High,
                ),
                $op,
                $matcher->identity(),
                $formatArgument,
                $proven
                    ? sprintf(
                        '%s cannot protect a format string that is itself built from a variable, and untrusted '
                            . 'input reaches this one.',
                        $matcher->describe(),
                    )
                    : sprintf(
                        '%s cannot protect a format string that is itself built from a variable. Taint analysis '
                            . 'could not account for where %s comes from, but the shape is unsafe regardless.',
                        $matcher->describe(),
                        OperandHelper::describe($formatArgument),
                    ),
            );
        }

        return $this->writeResult(
            $op->result,
            $incoming,
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf(
                    '%s was called with a non-literal format string, so it escapes nothing.',
                    $matcher->describe(),
                ),
                $call->arguments,
            ),
        );
    }

    private function transferPropagator(
        Op\Expr $op,
        CallTarget $call,
        ArgumentSelector $selector,
        Matcher $matcher,
        ?string $note,
    ): bool {
        $inputs = [];

        foreach ($selector->resolve($call->argumentCount()) as $index) {
            $argument = $call->argument($index);

            if ($argument !== null) {
                $inputs[] = $argument;
            }
        }

        $description = $note ?? sprintf('%s passes its argument through unchanged.', $matcher->describe());

        // array_keys() returns keys, so it reads the array's own taint and not
        // what element writes put into it. See transferArrayLiteral().
        if ($matcher->key() === 'function:array_keys' && $inputs !== []) {
            return $this->writeResult(
                $op->result,
                $this->state->taintOf($inputs[0]),
                new Provenance(TraceVerb::Propagate, $op, $description, $inputs),
            );
        }

        return $this->transferUnion($op, $inputs, $description);
    }

    /**
     * A call whose callee could not be named.
     *
     * The engine has genuinely lost the thread here, so anything it says next
     * is an assumption. Which assumption is `--dynamic-calls`, and the op is
     * marked imprecise either way so the finding carries the caveat with it.
     */
    private function transferDynamicCall(Op\Expr $op, CallTarget $call): bool
    {
        $this->imprecise = true;

        return match ($this->options->dynamicCalls) {
            DynamicCallPolicy::Clean => $this->writeResult($op->result, TaintSet::empty()),
            DynamicCallPolicy::Propagate => $this->transferUnion(
                $op,
                $call->arguments,
                sprintf(
                    'Call to %s could not be resolved, so %s (--dynamic-calls=propagate).',
                    $call->name(),
                    DynamicCallPolicy::Propagate->describe(),
                ),
            ),
            DynamicCallPolicy::Tainted => $this->writeResult(
                $op->result,
                TaintSet::allDataflowKinds(),
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf(
                        'Call to %s could not be resolved, so %s (--dynamic-calls=tainted).',
                        $call->name(),
                        DynamicCallPolicy::Tainted->describe(),
                    ),
                    $call->arguments,
                ),
            ),
        };
    }

    private function transferUserCall(Op\Expr $op, CallTarget $call): bool
    {
        $key = $call->userFunctionKey;

        if ($key === null) {
            return $this->writeResult($op->result, TaintSet::empty());
        }

        $summary = $this->summaries->get($key);

        if ($summary === null) {
            // Bottom of the lattice: the first interprocedural round has not
            // reached this callee yet.
            return $this->writeResult($op->result, TaintSet::empty());
        }

        if ($summary->imprecise) {
            $this->imprecise = true;
        }

        $result = $summary->introduces();
        $contributors = [];
        $viaParameters = [];
        $anyArgumentTainted = false;
        $changed = false;

        foreach ($call->arguments as $index => $argument) {
            // Both slots: the callee receives the whole value, and an array
            // passed in arrives with its elements attached. Reading only the
            // own slot loses every flow through `f( array( $_GET['v'] ) )`.
            $argumentTaint = $this->state->effectiveTaintOf($argument);

            if ($argumentTaint->isEmpty()) {
                continue;
            }

            $anyArgumentTainted = true;

            $returned = $argumentTaint->intersect($summary->returnTaintFor($index));

            if (! $returned->isEmpty()) {
                $result = $result->union($returned);
                $contributors[] = $argument;
                $viaParameters[] = $index;
            }

            $this->reportSummarySinks($op, $call, $summary, $index, $argument, $argumentTaint);
            $changed = $this->applySummaryProperties($op, $summary, $index, $argument, $argumentTaint)
                || $changed;
        }

        $result = self::withoutUnearnedEscapeMarkers($result, $anyArgumentTainted);

        $changed = $this->applySummaryByRefEffects($op, $call, $summary) || $changed;

        if ($result->isEmpty()) {
            return $this->writeResult($op->result, $result) || $changed;
        }

        return $this->writeResult(
            $op->result,
            $result,
            new Provenance(
                TraceVerb::Return_,
                $op,
                $this->describeReturn($summary, $viaParameters, $result),
                $contributors,
                callee: $summary->displayName,
                parameterIndex: $viaParameters[0] ?? null,
            ),
        ) || $changed;
    }

    /**
     * Write a callee's out-parameters back onto the caller's arguments.
     *
     * ```php
     * function fill( array &$out ) { $out[] = $_GET['x']; }
     *
     * $values = [];
     * fill( $values );
     * echo $values[0];      // reported now; silent before
     * ```
     *
     * Two contributions per out-parameter: what the callee moved into it from
     * another argument, and what it put there from sources in its own body. The
     * first is intersected with what the caller actually passed, so a parameter
     * that only ever carries HTML does not hand back SQL.
     *
     * Adds rather than sets, for the same reason the catalogue's [[byref]]
     * effects do: SSA gives the write no operand of its own.
     *
     * The element slot, because an out-parameter is nearly always an array and
     * the caller reads `$out[0]` rather than `$out`.
     */
    private function applySummaryByRefEffects(Op\Expr $op, CallTarget $call, FunctionSummary $summary): bool
    {
        $changed = false;

        foreach ($summary->byRefParameters() as $target) {
            $argument = $call->argument($target);

            if ($argument === null) {
                continue;
            }

            $taint = $summary->byRefIntroduces($target);
            $contributors = [];

            foreach ($call->arguments as $index => $source) {
                $moved = $this->state->effectiveTaintOf($source)->intersect($summary->byRefTaintFrom($index, $target));

                if (! $moved->isEmpty()) {
                    $taint = $taint->union($moved);
                    $contributors[] = $source;
                }
            }

            if ($taint->isEmpty()) {
                continue;
            }

            $provenance = new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf(
                    '%s writes %s back through by-reference parameter %d.',
                    $summary->displayName,
                    $taint->describe(),
                    $target + 1,
                ),
                $contributors,
            );

            $changed = $this->state->addContainerTaint($argument, $taint, $provenance) || $changed;
        }

        return $changed;
    }

    /**
     * A trace step that says nothing but "propagated" teaches the reader
     * nothing. Name the parameter it went in as, and what came back out.
     *
     * @param list<int> $viaParameters
     */
    private function describeReturn(FunctionSummary $summary, array $viaParameters, TaintSet $result): string
    {
        if ($viaParameters === []) {
            return sprintf(
                '%s() introduces %s taint regardless of its arguments.',
                $summary->displayName,
                $result->describe(),
            );
        }

        $context = $this->functions->get($summary->key);
        $names = array_map(
            static fn (int $index): string => $context === null
                ? sprintf('parameter %d', $index)
                : sprintf('parameter %d (%s)', $index, $context->parameterName($index)),
            $viaParameters,
        );

        return sprintf(
            'Passed to %s() as %s. That parameter reaches the return value, so the taint comes back out.',
            $summary->displayName,
            implode(' and ', $names),
        );
    }

    /**
     * A sink inside a callee, reachable from an argument at this call site.
     *
     * The finding is reported at the sink's own location inside the callee,
     * because that is the line that needs the fix, with the call site carried
     * in the trace.
     */
    private function reportSummarySinks(
        Op\Expr $op,
        CallTarget $call,
        FunctionSummary $summary,
        int $index,
        Operand $argument,
        TaintSet $argumentTaint,
    ): void {
        if (! $this->collecting || ! $this->collectFindings) {
            return;
        }

        foreach ($summary->sinksFor($index) as $reference) {
            if (! $argumentTaint->has($reference->kind)) {
                continue;
            }

            $key = $reference->identityKey() . '|' . spl_object_id($op) . '|' . $index;

            if (isset($this->emitted[$key])) {
                continue;
            }

            $this->emitted[$key] = true;

            $callStep = $this->traces->step(
                TraceVerb::Call,
                $op,
                $argumentTaint,
                sprintf(
                    'Passed to %s as parameter %d.',
                    $summary->displayName,
                    $index,
                ),
                $summary->displayName,
                $index,
            );

            $sinkStep = new TraceStep(
                TraceVerb::Sink,
                $reference->relativeFile,
                $reference->line,
                $reference->column,
                $reference->endColumn,
                $reference->snippet,
                sprintf(
                    'Reaches %s inside %s with %s taint intact.',
                    $reference->sinkIdentity,
                    $reference->functionDisplayName,
                    $reference->kind->value,
                ),
                TaintSet::of($reference->kind),
            );

            $trace = [
                ...$this->traces->build($argument, $reference->kind, $callStep),
                $sinkStep,
            ];

            $this->findings[] = new Finding(
                $reference->ruleId,
                $this->registry->rule($reference->ruleId),
                $reference->severity,
                $reference->kind,
                $reference->relativeFile,
                $reference->line,
                $reference->column,
                $reference->endColumn,
                $this->registry->ruleMessage($reference->ruleId),
                $trace,
                Fingerprint::compute(
                    $reference->ruleId,
                    $reference->relativeFile,
                    $reference->sinkIdentity,
                    $reference->snippet,
                ),
                $this->imprecise || $reference->imprecise,
                $reference->sinkIdentity,
            );
        }
    }

    // -------------------------------------------------------------------
    // Sink reporting
    // -------------------------------------------------------------------

    /**
     * Does this call hand the value to somebody else before returning it?
     */
    private function voidsEscaping(Matcher $matcher, CallTarget $call): bool
    {
        // An escaper never voids escaping, even though core ends esc_html() and
        // esc_attr() with `return apply_filters( 'esc_html', ... )` and the
        // generated list therefore contains them. That is literally true — a
        // plugin can hook `esc_html` — and acting on it would make every
        // escaper void its own work, which is the one reading that cannot be
        // right. A site with a hostile `esc_html` filter has a problem this
        // rule cannot usefully report at each of ten thousand call sites.
        if ($this->registry->sanitizer($matcher) !== null) {
            return false;
        }

        if ($this->registry->dispatcher($matcher)?->hook === true) {
            return true;
        }

        if ($matcher->kind !== MatcherKind::Func) {
            return false;
        }

        // Parameter positions no longer gate this — the return is what matters,
        // not what was handed in — but a function whose filtered value comes
        // from nothing at all still returns filtered content, so the entry
        // existing is the test.
        return $this->registry->filterableParameters($matcher->name) !== null;
    }

    /**
     * What an extension point returns is not safe to print.
     *
     * This started out narrower — trade `escaped` for `escape_voided` when an
     * escaped value passes *through* a filter — and that is only half of it:
     *
     * ```php
     * $safe   = esc_html( $value );
     * $suffix = apply_filters( 'fx_suffix', '' );   // nothing escaped went in
     * echo $safe . $suffix;                          // still unsafe
     * ```
     *
     * Nothing escaped goes through that filter. The *return* is the problem: a
     * plugin decides what `fx_suffix` produces, and concatenating it with an
     * escaped string makes the whole string unescaped again. Asking what went
     * in misses every case where the filter supplies a fragment rather than
     * transforming one.
     *
     * So the result of a hook dispatch, a shortcode expansion, or a core
     * function that returns filtered content carries `escape_voided` whatever
     * its arguments were. Escaping *after* the call clears it, which is the
     * order the practice asks for.
     *
     * Applied in writeResult() rather than in one of the role branches because
     * a dispatcher can also be a propagator or resolve to callees, and all of
     * those paths end here.
     */
    private function voidEscaping(TaintSet $taint): TaintSet
    {
        if ($this->voidingCall === null) {
            return $taint;
        }

        // `escaped` is carried across from the arguments rather than merely
        // kept, because an unmodelled callee returns clean and would otherwise
        // drop the marker before the sink ever sees it — `do_shortcode( $safe )`
        // arrived at the echo carrying the voiding and no evidence that anyone
        // had escaped anything.
        //
        // Both are needed at the sink: escaping happened, and something a third
        // party controls reached the same output. Without that pairing,
        // `echo get_option( 'x' )` reports twice — once as unescaped output,
        // which is the real finding, and once as voided escaping, which adds
        // nothing to it.
        $incoming = $this->state->unionOf($this->voidingCall->arguments);
        $voided = $taint->union(TaintSet::of(TaintKind::EscapeVoided));

        return $incoming->has(TaintKind::Escaped)
            ? $voided->union(TaintSet::of(TaintKind::Escaped))
            : $voided;
    }

    /**
     * The trace step for the call that voided the escaping.
     *
     * `wp_sprintf()` is the case that prompted this. It looks like `sprintf()`
     * and is not:
     *
     *     $_fragment = apply_filters( 'wp_sprintf', $fragment, $arg );
     *     if ( $_fragment !== $fragment ) {
     *         $fragment = $_fragment;      // the callback's return, verbatim
     *     }
     *
     * A theme escaping every argument and handing them to it is doing careful
     * work, and being told "this value was escaped and then filtered" with no
     * indication of which call did the filtering is not enough to act on.
     */
    private function voidProvenance(TaintSet $taint): ?Provenance
    {
        $call = $this->voidingCall;
        $op = $this->voidingOp;

        if ($call === null || $op === null) {
            return null;
        }

        $name = $call->matcher?->describe() ?? 'This call';

        return new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf(
                '%s runs a filter and returns what the filter gave back, so any escaping applied before this '
                    . 'point is no longer guaranteed. Escape after this call rather than before it.',
                $name,
            ),
            $call->arguments,
            callee: $name,
            imprecise: $taint->has(TaintKind::Unknown),
        );
    }

    /**
     * A named condition on whether a sink fires for this particular value.
     *
     * `unanchored`: an identifier with any fixed fragment in it is a different,
     * much smaller problem than one the attacker chooses outright.
     *
     * `unserialize_allows_objects`: a call that already forbids classes cannot
     * run a POP chain, and reporting it would tell people to do the thing they
     * have done.
     */
    private function sinkApplies(Sink $sink, Operand $operand): bool
    {
        return match ($sink->appliesBy) {
            Sink::UNANCHORED => ! $this->anchors->has($operand),
            Sink::UNSERIALIZE_ALLOWS_OBJECTS => $this->sinkCall === null || ! $this->forbidsClasses($this->sinkCall),
            Sink::ESCAPED_THEN_VOIDED => $this->state->effectiveTaintOf($operand)->has(TaintKind::Escaped),
            default => true,
        };
    }

    /**
     * `false`, however php-cfg chose to spell it.
     *
     * A bare `false` arrives as a temporary defined by a `ConstFetch`, not as a
     * boolean literal, so testing for `Operand\Literal` alone silently answers
     * no for the one spelling that actually appears in source.
     */
    private static function isFalse(Operand $operand): bool
    {
        if ($operand instanceof Operand\Literal) {
            return $operand->value === false;
        }

        $definition = OperandHelper::definingOp($operand);

        if (! $definition instanceof Op\Expr\ConstFetch) {
            return false;
        }

        $name = OperandHelper::literalString($definition->name);

        return $name !== null && strtolower($name) === 'false';
    }

    /**
     * Does this `unserialize()` call pass `allowed_classes => false`?
     *
     * Read from the options array at the call site. A value built elsewhere is
     * not followed: being wrong in the permissive direction would hide an
     * object injection, so anything unreadable counts as permitting objects.
     */
    private function forbidsClasses(CallTarget $call): bool
    {
        $options = $call->argument(1);
        $definition = $options === null ? null : OperandHelper::definingOp($options);


        if (! $definition instanceof Op\Expr\Array_) {
            return false;
        }

        foreach ($definition->keys as $index => $key) {
            if (! $key instanceof Operand || OperandHelper::literalString($key) !== 'allowed_classes') {
                continue;
            }

            $value = $definition->values[$index] ?? null;

            return $value instanceof Operand && self::isFalse($value);
        }

        return false;
    }

    private function reportCallSink(Sink $sink, Op $op, CallTarget $call, Matcher $matcher): void
    {
        // Carried on the instance because reportSink() is shared with construct
        // sinks, which have no call to hand.
        $this->sinkCall = $call;

        foreach ($sink->arguments->resolve($call->argumentCount()) as $index) {
            $argument = $call->argument($index);

            if ($argument === null) {
                continue;
            }

            $this->reportSink($sink, $op, $argument, $matcher->identity());
        }

        $this->sinkCall = null;
    }

    private function reportSink(Sink $sink, Op $op, Operand $operand, string $identity): void
    {
        $taint = $this->state->effectiveTaintOf($operand);

        if (! $taint->has($sink->kind)) {
            $this->checkQueryShape($sink, $op, $operand, $identity);

            return;
        }

        if (! $this->sinkApplies($sink, $operand)) {
            return;
        }

        // Did every path here validate the value? A guard clause is how careful
        // WordPress code constrains a request value, and it lives in the shape
        // of the control flow rather than in the value, so it is asked here
        // rather than propagated. See {@see GuardAnalyzer}.
        if ($this->guards->isGuarded($operand, $this->currentBlock)) {
            return;
        }

        $this->recordSinkReference($sink, $op, $identity);

        if (! $this->collecting || ! $this->collectFindings) {
            return;
        }

        $this->emit(
            $sink->ruleId,
            $sink->kind,
            $sink->severity,
            $op,
            $identity,
            $operand,
            sprintf('Reaches %s with %s taint intact.', $identity, $sink->kind->value),
        );
    }

    /**
     * A database query that carries no SQL taint but is still built by
     * interpolating something the engine could not account for.
     *
     * Reported at high rather than critical severity: unlike a taint finding it
     * has no proven path from a source, so it is a "look at this" rather than a
     * "this is exploitable".
     */
    private function checkQueryShape(Sink $sink, Op $op, Operand $operand, string $identity): void
    {
        if (! $this->collecting || $sink->kind !== TaintKind::Sql) {
            return;
        }

        // Checked before the collecting guard, because a summary pass has to
        // record it: the escaper that creates the risk lives in the callee, so
        // the caller can only learn about it from the summary. Recorded under
        // `sql` rather than `sql_unquoted`, because `sql` is what the caller
        // passes in — the callee is what turns one into the other.
        $unquoted = $this->queryShapes->unquotedComponent(
            $operand,
            fn (Operand $component): bool => $this->state
                ->effectiveTaintOf($component)
                ->has(TaintKind::SqlUnquoted),
        );

        if ($unquoted !== null) {
            $this->recordSinkReference(
                new Sink(
                    $sink->matcher,
                    $sink->arguments,
                    TaintKind::Sql,
                    Severity::Critical,
                    self::UNPREPARED_QUERY_RULE,
                ),
                $op,
                $identity,
            );
        }

        if (! $this->collectFindings) {
            return;
        }

        $unaccounted = $this->queryShapes->unaccountedComponent($operand, $this->context, $this->types);

        if ($unaccounted !== null) {
            $this->emit(
                self::UNPREPARED_QUERY_RULE,
                TaintKind::Sql,
                Severity::High,
                $op,
                $identity,
                $unaccounted,
                sprintf(
                    'A variable is interpolated into the query passed to %s(). Taint analysis could not account for '
                        . 'where %s comes from, but the shape is unsafe regardless.',
                    $identity,
                    OperandHelper::describe($unaccounted),
                ),
            );

            return;
        }

        if ($unquoted === null) {
            return;
        }

        $this->emit(
            self::UNPREPARED_QUERY_RULE,
            TaintKind::Sql,
            Severity::Critical,
            $op,
            $identity,
            $unquoted,
            sprintf(
                '%s was escaped with esc_sql() or an equivalent and then interpolated into the query passed to '
                    . '%s() with no quotes around it. Those functions escape quotes; with none present there is '
                    . 'nothing for them to escape, and `1 OR 1=1` reaches the database intact. Use prepare() with '
                    . 'a %%d or %%s placeholder.',
                OperandHelper::describe($unquoted),
                $identity,
            ),
        );
    }

    /**
     * Record that the seeded parameter reached a sink, for the caller's
     * benefit. Only meaningful while summarising.
     */
    /**
     * A probe run reached a property with the seeded parameter's taint.
     *
     * Keyed so the same write in a loop, or across the fixed point's rounds,
     * records once — a growing list would make the summary compare unequal to
     * itself and the interprocedural fixed point would never settle.
     */
    private function recordPropertyReference(?string $class, string $property): void
    {
        if ($this->seedParameterIndex === null) {
            return;
        }

        $this->propertiesReached[strtolower($class ?? '?') . '::' . $property] = [$class, $property];
    }

    private function recordSinkReference(Sink $sink, Op $op, string $identity): void
    {
        if (! $this->collecting || $this->seedParameterIndex === null) {
            return;
        }

        $position = OperandHelper::position($op, $this->context->file->sourceMap);

        $this->sinksReached[] = new SinkReference(
            $sink->ruleId,
            $sink->kind,
            $sink->severity,
            $identity,
            $this->context->file->path,
            $this->context->file->relativePath,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            trim($this->context->file->sourceMap->line($position['line'])),
            $this->context->displayName,
            $this->imprecise,
        );
    }

    /**
     * Name the call that voided the escaping, in the message itself.
     *
     * "This value was escaped and then filtered" leaves the reader with the
     * one question that matters — filtered *where?* — and a theme that escaped
     * every argument before handing them to `wp_sprintf()` has no way to guess
     * that `wp_sprintf()` is the filter. The trace has carried the answer since
     * the void started recording a callee; this puts it on the line people read
     * first.
     *
     * The earliest step is the right one: it is where the marker entered, so
     * when the void happened inside a callee that callee gets named rather than
     * whatever passed the value along afterwards.
     *
     * @param list<TraceStep> $trace
     */
    private static function messageFor(string $message, TaintKind $kind, array $trace): string
    {
        if ($kind !== TaintKind::EscapeVoided) {
            return $message;
        }

        foreach ($trace as $step) {
            if ($step->callee !== null && $step->kinds->has(TaintKind::EscapeVoided)) {
                return sprintf(
                    'This value was escaped and then passed through %s, which runs a filter, so the escaping no '
                        . 'longer holds.',
                    $step->callee,
                );
            }
        }

        return $message;
    }

    private function emit(
        string $ruleId,
        TaintKind $kind,
        Severity $severity,
        Op $op,
        string $identity,
        Operand $operand,
        string $sinkDescription,
    ): void {
        $position = OperandHelper::position($op, $this->context->file->sourceMap);
        $snippet = trim($this->context->file->sourceMap->line($position['line']));

        $key = implode('|', [$ruleId, $kind->value, (string) $position['line'], (string) $position['column']]);

        if (isset($this->emitted[$key])) {
            return;
        }

        $this->emitted[$key] = true;

        $sinkStep = $this->traces->sinkStep($op, TaintSet::of($kind), $sinkDescription);
        $trace = $this->traces->build($operand, $kind, $sinkStep);

        $this->findings[] = new Finding(
            $ruleId,
            $this->registry->rule($ruleId),
            $severity,
            $kind,
            $this->context->file->relativePath,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            self::messageFor($this->registry->ruleMessage($ruleId), $kind, $trace),
            $trace,
            Fingerprint::compute($ruleId, $this->context->file->relativePath, $identity, $snippet),
            $this->imprecise,
            $identity,
        );
    }
}
