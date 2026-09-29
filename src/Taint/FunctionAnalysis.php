<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\CompatibilityVisitor;
use Enshrined\WpTaint\Cfg\IncludeGraph;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Fingerprint;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Hooks\RestRouteTable;
use Enshrined\WpTaint\Registry\DispatchReturn;
use Enshrined\WpTaint\Registry\InternalFunction;
use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\MatcherKind;
use Enshrined\WpTaint\Registry\Propagator;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\Sanitizer;
use Enshrined\WpTaint\Registry\Sink;
use Enshrined\WpTaint\Registry\Source;
use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

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

    /**
     * A request value naming a column or table, escaped correctly or not. See
     * {@see checkQueryShape()}.
     */
    private const IDENTIFIER_CHOICE_RULE = 'wp.sqli.identifier-choice';

    /** How far {@see throughAssignments} follows `$a = $b = $c` before giving up. */
    private const MAX_ASSIGNMENT_HOPS = 16;

    /**
     * The keys each computed key can hold, by operand: see namedKeys().
     *
     * @var array<int, non-empty-list<int|string>|null>
     */
    private array $namedKeys = [];

    /**
     * The stored value each property read last put on its result, by op, so a
     * pass that finds it unchanged does not copy it again.
     *
     * @var array<int, Shape>
     */
    private array $propertyReads = [];

    /**
     * Each property's value across its class hierarchy, with the values it
     * was joined from, so an unchanged hierarchy hands back the same shape.
     *
     * @var array<string, array{list<Shape>, Shape}>
     */
    private array $storedValues = [];

    /**
     * Properties the seeded parameter reached, keyed to deduplicate, with
     * what reached each.
     *
     * @var array<string, array{0: string|null, 1: string, 2: Shape}>
     */
    private array $propertiesReached = [];

    /**
     * Closure captures the seeded parameter reached, keyed so a loop or a
     * later round records each once, with the kinds that reached each. See
     * {@see AnalysisResult::$capturesReached}.
     *
     * @var array<string, array{0: string, 1: string, 2: TaintSet}>
     */
    private array $capturesReached = [];

    /**
     * Shared scopes the seeded parameter reached, keyed so a loop or a later
     * round records each once, with what reached each. See
     * {@see AnalysisResult::$scopesReached}.
     *
     * @var array<string, array{0: string, 1: string, 2: string, 3: Shape}>
     */
    private array $scopesReached = [];

    private TaintState $state;

    private ClassTypeMap $types;

    /** @var list<Finding> */
    private array $findings = [];

    /** @var list<SinkReference> */
    private array $sinksReached = [];

    /** @var array<string, true> */
    private array $emitted = [];

    private TaintSet $returnTaint;

    /**
     * What the returned array holds below its own taint: its elements, each
     * under its key, and its keys.
     */
    private Shape $returnShape;

    /** Null until the first return is seen; then AND-ed across every return. */
    private ?bool $returnAnchored = null;

    private bool $imprecise = false;

    /** @var list<AnalysisWarning> */
    private array $warnings = [];

    private readonly QueryShapeInspector $queryShapes;

    private readonly LiteralAnchor $anchors;

    private readonly GuardAnalyzer $guards;

    private readonly CapabilityGuard $capabilityGuards;

    /**
     * The same question asked of site-wide grants only, for an option write.
     * Built on the first write, because most bodies never make one.
     */
    private ?CapabilityGuard $siteWideGuards = null;

    /**
     * The collections of loops that rebuild an array under their own key:
     * see {@see rebuildLoops()}. Null until first asked.
     *
     * @var array<int, true>|null
     */
    private ?array $rebuildLoops = null;

    /**
     * Per such loop's collection, the number each literal key's element is
     * labelled with. Handed out once and never reused, so a number names one
     * element of one loop for the whole run.
     *
     * @var array<int, array<int|string, int>>
     */
    private array $loopElementNumbers = [];

    private int $nextElementNumber = 0;

    /** The block being walked, so a sink can ask what guarded the path to it. */
    private ?Block $currentBlock = null;

    /**
     * The variables that can change out of sight: see referencedNames().
     *
     * @var array<string, true>|null
     */
    private ?array $referencedNames = null;

    private bool $referencedNamesFound = false;

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
     * The residuals this probe run may have undone on the way. See
     * {@see FunctionSummary::$revertedResiduals}.
     */
    private ?TaintSet $revertedResiduals = null;

    /**
     * Set while a call op with several possible callees is being transferred,
     * so their results accumulate on the shared operand instead of the last one
     * visited overwriting the rest. See {@see transferCalls()}.
     */
    private bool $unionResultWrites = false;

    /**
     * The result writes of each callee in the current union, held back until
     * every callee has been visited. See {@see flushUnionWrites()}.
     *
     * @var list<array{operand: Operand, taint: TaintSet, provenance: ?Provenance}>
     */
    private array $unionWrites = [];

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

    private RestParameterSanitizer $restParameters;

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
        private readonly ?RestRouteTable $restRoutes = null,
        private readonly ?AdministratorReach $administrators = null,
        /**
         * In a probe run, the parts the seeded parameter is read through,
         * each seeded under its own number: see {@see ParameterParts}.
         *
         * @var list<list<int|string>>
         */
        private readonly array $seedParts = [],
    ) {
        $this->state = new TaintState();
        $this->restParameters = new RestParameterSanitizer($registry, $summaries);
        $this->types = new ClassTypeMap();
        $this->queryShapes = new QueryShapeInspector(
            $literals,
            new OriginClassifier($registry, $resolver, $properties, $receivers, $functions->classHierarchy()),
            $resolver->values(),
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
        $this->guards = new GuardAnalyzer($resolver->values());
        $this->capabilityGuards = new CapabilityGuard($registry, $callGraph);
        $this->returnTaint = TaintSet::empty();
        $this->returnShape = Shape::empty();
        $this->returnAnchored = null;
        $this->blocks = BlockOrder::of($this->context->func->cfg);
        $this->guards->forFunction($this->blocks);
        $this->capabilityGuards->forFunction($this->blocks);
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

        // A loop's element numbers mean something only in this run, and
        // everything below outlives it in a summary: see
        // TaintSet::withoutElements().
        $plain = static fn (?TaintSet $taint): ?TaintSet => $taint?->withoutElements();
        $properties = array_map(
            static fn (array $reference): array => [
                $reference[0],
                $reference[1],
                $reference[2]->mapSets(static fn (TaintSet $taint): TaintSet => $taint->withoutElements()),
            ],
            array_values($this->propertiesReached),
        );
        $captures = array_map(
            static fn (array $reference): array => [$reference[0], $reference[1], $reference[2]->withoutElements()],
            array_values($this->capturesReached),
        );
        $scopes = array_map(
            static fn (array $reference): array => [
                $reference[0],
                $reference[1],
                $reference[2],
                $reference[3]->mapSets(static fn (TaintSet $taint): TaintSet => $taint->withoutElements()),
            ],
            array_values($this->scopesReached),
        );

        return new AnalysisResult(
            $this->findings,
            $this->returnTaint->withoutElements(),
            $this->sinksReached,
            $this->imprecise,
            array_map(static fn (TaintSet $taint): TaintSet => $taint->withoutElements(), $this->byRefTaint()),
            $this->warnings,
            $this->state,
            $this->returnAnchored ?? false,
            $properties,
            $captures,
            $scopes,
            $this->returnShape->mapSets(static fn (TaintSet $taint): TaintSet => $taint->withoutElements()),
            $plain($this->revertedResiduals),
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

        // A probe run of a closure seeds one of its parameters with every
        // kind of taint. Written back to the function that made the closure,
        // that seed became an assertion about the maker's variables, whatever
        // the closure was later called with. Recorded here; the call site
        // publishes what it actually passed. File-level code has no
        // parameters, so it is never probed.
        if ($this->seedParameterIndex !== null) {
            foreach ($named['taint'] as $name => $value) {
                if (isset($assigned[$name])) {
                    $this->recordScopeReference('out', $this->context->key, $name, $value);
                }
            }

            return;
        }

        $scope = [];
        $origins = [];

        foreach ($named['taint'] as $name => $value) {
            if (! isset($assigned[$name])) {
                continue;
            }

            $scope[$name] = $value;

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
     * Each variable's own taint goes on every operand of its name, where an
     * assignment overwrites it. Its elements go only on an operand nothing in
     * this body writes, the value as it arrived, since elements only ever
     * grow: `$args = array( 'id' => 7 )` in the template must not read the
     * includer's `$args['id']`.
     *
     * @param array<string, Shape> $scope
     */
    private function seedScope(array $scope, string $description, string $originKey): void
    {
        if ($scope === []) {
            return;
        }

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

                    $this->state->add($operand, $scope[$name]->own(), $provenance);

                    // Under their keys: seeding them as one set would throw
                    // the keys away at the boundary, and every key would read
                    // as tainted again.
                    if ($operand->ops === []) {
                        $this->state->addShape($operand, $scope[$name]->structure(), $provenance);
                    }
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

        // A probe run's seed is a question, not a value the code holds, and
        // publishing it told the included file that every variable derived
        // from the parameter carried every kind of taint, even when every
        // caller passed a literal. Recorded instead, and published by each
        // caller with what it passed; see {@see applySummaryScopes}.
        if ($this->seedParameterIndex !== null) {
            foreach ($targets as $target) {
                foreach ($visible['taint'] as $name => $value) {
                    $this->recordScopeReference('in', strtolower($target . '::{main}'), $name, $value);
                }
            }

            return false;
        }

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
     * Note that the seeded parameter reached a shared scope, and with what.
     * See {@see FunctionSummary::$paramToScope} for what the parts mean.
     */
    private function recordScopeReference(string $table, string $key, string $name, Shape $value): void
    {
        if ($value->isEmpty()) {
            return;
        }

        $id = FunctionSummary::scopeKey([$table, $key, $name]);
        $joined = ($this->scopesReached[$id][3] ?? Shape::empty())->join($value);
        $this->scopesReached[$id] = [$table, $key, $name, $joined];
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
     * beginning "$title was in scope" and ending there. Each variable is a
     * shape: its own taint, and its elements under their keys.
     *
     * @return array{taint: array<string, Shape>, origins: array<string, list<TraceStep>>}
     */
    private function namedScopeWithOrigins(): array
    {
        $own = [];
        $parts = [];
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

                    $taint = $this->state->taintOf($operand);
                    $shape = $this->state->shapeOf($operand);

                    if ($taint->isEmpty() && $shape->isEmpty()) {
                        continue;
                    }

                    // Most named values are scalars, so the own taint is
                    // gathered as a set, and only a value with elements
                    // joins a shape.
                    $own[$name] = ($own[$name] ?? TaintSet::empty())->union($taint);

                    if (! $shape->isEmpty()) {
                        $parts[$name] = ($parts[$name] ?? Shape::empty())->join($shape);
                    }

                    if (! isset($origins[$name])) {
                        $origin = $this->scopeTrace($op, $operand, $name, $taint->union($shape->flatten()));

                        if ($origin !== []) {
                            $origins[$name] = $origin;
                        }
                    }
                }
            }
        }

        $scope = [];

        foreach ($own as $name => $taint) {
            $scope[$name] = Shape::node($taint, $parts[$name] ?? Shape::empty());
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

        $seed = TaintSet::allDataflowKinds()->with(TaintKind::Seed);
        $provenance = new Provenance(
            TraceVerb::Source,
            $param,
            sprintf(
                'Parameter %d (%s) of %s, assumed tainted while summarising the function.',
                $this->seedParameterIndex,
                $this->context->parameterName($this->seedParameterIndex),
                $this->context->displayName,
            ),
        );

        if ($this->seedParts === []) {
            $this->state->set($param->result, $seed, $provenance);

            return;
        }

        // Part 0 is the parameter's own taint, which every part inherits.
        // Each part the body reads the parameter through is seeded as well,
        // under its own number, so the summary can say which reached what.
        $this->state->set($param->result, $seed->fromPart(0), $provenance);

        foreach ($this->seedParts as $position => $path) {
            $part = self::shapeAtPart($path, $seed->fromPart($position + 1), $this->seedParts);
            $this->state->addShape($param->result, $part, $provenance);
        }
    }

    /**
     * A shape holding `$taint` at `$path` and nothing else: under each literal
     * key in turn, under any element for {@see ParameterParts::ANY}, under the
     * element standing for the keys no part names for
     * {@see ParameterParts::OTHERS}, and in the keys for a path that ends in
     * {@see ParameterParts::KEYS}.
     *
     * @param list<int|string>       $path
     * @param list<list<int|string>> $parts every part of the parameter
     */
    private static function shapeAtPart(array $path, TaintSet $taint, array $parts): Shape
    {
        $last = $path === [] ? null : $path[count($path) - 1];
        $shape = $last === ParameterParts::KEYS ? Shape::keys($taint) : Shape::of($taint);
        $steps = $last === ParameterParts::KEYS ? array_slice($path, 0, -1) : $path;

        foreach (array_reverse($steps, true) as $at => $step) {
            $shape = match ($step) {
                ParameterParts::ANY => Shape::rest($shape),
                ParameterParts::OTHERS => Shape::element(
                    Shape::others(ParameterParts::namedUnder($parts, array_slice($steps, 0, $at))),
                    $shape,
                ),
                default => Shape::element($step, $shape),
            };
        }

        return $shape;
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
            ?? $this->state->partProvenanceOf($value, null);

        if ($provenance === null) {
            return false;
        }

        // One way only. The collection's shape is never *set* by anything —
        // writes into it all go through addShape(), which grows — so adding
        // here cannot start a fight. Pushing back the other
        // way would, because an ordinary assignment to the loop variable owns
        // that operand and would reset it every pass.
        return $this->state->addShape($collection, Shape::rest(Shape::of($held)), $provenance);
    }

    /**
     * `$a = &$b`: one slot under two names, all of it.
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

        // Every element travels with the slot, each with the write behind it.
        // Sharing only those under a computed key lost
        // `$d = &$c; $d['j'] = $_GET['y']; echo $c['j'];`.
        $shape = $this->state->shapeOf($left)->join($this->state->shapeOf($right));
        $changed = $this->state->addShape($left, $shape) || $changed;

        return $this->state->addShape($right, $shape) || $changed;
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
     *
     * Each operand brings only what a guard on every way here leaves it. A
     * guard proves what it proves about the value it tested, not about a
     * value written after it, so a join of the two has to take the proof from
     * the operand that was tested:
     *
     *     if ( ! ctype_digit( $id ) ) { return; }
     *     if ( $pad ) { $id = str_pad( $id, 8, '0' ); }
     *     echo $id;
     */
    private function applyPhi(Op\Phi $phi): bool
    {
        $incoming = [];
        $merged = TaintSet::empty();
        $parts = Shape::empty();

        foreach ($phi->vars as $var) {
            if (! $var instanceof Operand) {
                continue;
            }

            $incoming[] = $var;
            $proof = $this->proofFor($var, $this->currentBlock);

            // An array keeps its parts through a join, so one built in a loop
            // or an `if` still knows its keys after it. A value a guard vouches
            // for is a scalar, so what the guard lets through is one set.
            if ($proof !== null) {
                $merged = $merged->union(self::guarded($this->state->effectiveTaintOf($var), $proof));

                continue;
            }

            $merged = $merged->union($this->state->taintOf($var));
            $parts = $parts->join($this->state->shapeOf($var));
        }

        // The split-escape rule reads the merge as a whole, as a sink would.
        // When it drops `escaped` there, it drops it from every part too.
        $flat = $merged->union($parts->flatten());

        if (! self::withoutSplitEscapeClaim($flat, $incoming, $this->state)->equals($flat)) {
            $escaped = TaintSet::of(TaintKind::Escaped);
            $merged = $merged->without($escaped);
            $parts = $parts->without($escaped);
        }
        $provenance = new Provenance(
            TraceVerb::Propagate,
            $phi,
            'Branches merge here; the value carries the taint of whichever path was taken.',
            $incoming,
        );
        $changed = $this->state->addShape($phi->result, $parts, $provenance);

        if ($merged->isEmpty()) {
            return $this->state->set($phi->result, $merged) || $changed;
        }

        return $this->state->set($phi->result, $merged, $provenance) || $changed;
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
     * filter. Three blocks in a real theme are exactly this, all of them
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
            // An int cast ends every payload and settles nothing about whose
            // row the number names, so the object-id kind rides through it.
            $op instanceof Op\Expr\Cast\Int_,
            $op instanceof Op\Expr\Cast\Double => $this->transferNumericCast($op),
            $op instanceof Op\Expr\Cast\Bool_ => $this->state->set($op->result, TaintSet::empty()),
            $op instanceof Op\Expr\Cast => $this->transferPassThrough(
                $op,
                $op->expr,
                'Cast to a string keeps the value intact.',
            ),
            $op instanceof Op\Iterator\Value => $this->transferIteratorValue($op),
            $op instanceof Op\Iterator\Key => $this->transferIteratorKey($op),
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

    /**
     * `(int) $_POST['id']` produces a number that cannot carry a quote or a
     * tag, and still names exactly the row the request chose. Every payload
     * kind ends here; the object-id kind is an authorization claim rather than
     * a payload, so it is the one thing the cast keeps.
     */
    private function transferNumericCast(Op\Expr\Cast $op): bool
    {
        $kept = $this->state->effectiveTaintOf($op->expr)->intersect(TaintSet::of(TaintKind::ObjectId));

        if ($kept->isEmpty()) {
            return $this->state->set($op->result, $kept);
        }

        return $this->state->set(
            $op->result,
            $kept,
            new Provenance(
                TraceVerb::Propagate,
                $op,
                'Cast to a number, which ends every payload and still names the row the request chose.',
                [$op->expr],
            ),
        );
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

        // A value checked on every path to here against a guard is one of what
        // the guard admits, wherever it is written: see GuardAnalyzer. What
        // survives is what the check leaves possible, kind by kind.
        // Otherwise `$query['orderby'] = $params['orderby']` behind an
        // allowlist carried the request into every query built from $query.
        $proof = $op instanceof Op\Expr\Assign ? $this->proofFor($value, $this->currentBlock) : null;
        $taint = self::guarded($this->state->taintOf($value), $proof);

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
        $rest = $this->state->shapeOf($value)->restPart();
        $container = self::guarded($rest->flatten(), $proof);

        if (! $container->isEmpty()) {
            // Unguarded, the elements under computed keys keep what they hold
            // below themselves. A guard vouches for a scalar, so what it lets
            // through is one set.
            $kept = Shape::rest($proof === null
                ? Shape::node($rest->own(), $rest->structure(), $provenance)
                : Shape::of($container, $provenance));
            $changed = $this->state->addShape($op->var, $kept) || $changed;
            $changed = $this->state->addShape($op->result, $kept) || $changed;
        }

        // The per-key slots travel with the array. Without this `$b = $a` would
        // lose the precision and fall back to the whole-array answer. A value
        // that passed a guard is a scalar, so it has none worth carrying.
        if ($proof === null) {
            $changed = $this->state->copyElements($value, $op->var) || $changed;
            $changed = $this->state->copyElements($value, $op->result) || $changed;
        }

        // So do the keys, each with the write that made it. A guard vouches
        // for a scalar, which has none.
        $shape = $this->state->shapeOf($value);
        $keys = $proof === null ? $shape->keysTaint() : TaintSet::empty();

        if (! $keys->isEmpty()) {
            $kept = Shape::keys($keys, $shape->keysProvenance());
            $changed = $this->state->addShape($op->var, $kept, $provenance) || $changed;
            $changed = $this->state->addShape($op->result, $kept, $provenance) || $changed;
        }

        // A property keeps the whole value, its elements under their keys, so
        // a read of one element sees only what that element was given. A
        // guard vouches for a scalar, so what it lets through is one set.
        $written = $proof === null
            ? Shape::node($taint, $shape)
            : Shape::of($taint->union($container));

        return $this->propagateIndirectWrite($op, $taint->union($container)->union($keys), $written) || $changed;
    }

    /**
     * What the checks on every way here prove about the value, as of this
     * pass.
     *
     * A proof that rests on a list staying clean holds only while it does:
     * see {@see CharacterProof::requiringClean()}. Taint only grows across the
     * passes, so such a proof can be lost and never regained, and the fixed
     * point stays monotone.
     */
    private function proofFor(Operand $operand, ?Block $block): ?CharacterProof
    {
        $proof = $this->guards->proofFor($operand, $block);

        if ($proof === null) {
            return null;
        }

        foreach ($proof->cleanLists as $list) {
            if (! $this->state->effectiveTaintOf($list)->isEmpty()) {
                return null;
            }
        }

        return $proof;
    }

    /**
     * What survives the checks on every way here: what they leave possible,
     * kind by kind. See {@see CharacterProof}. An object id always survives;
     * it names a row rather than carrying a payload.
     */
    private static function guarded(TaintSet $taint, ?CharacterProof $proof): TaintSet
    {
        return $proof === null ? $taint : $proof->apply($taint);
    }

    /**
     * The taint of a computed key an element write used, recorded on the
     * array's keys. `foreach` keys and array_keys() read it.
     */
    private function recordKeyTaint(Op\Expr\Assign|Op\Expr\AssignRef $op, Op\Expr\ArrayDimFetch $target): bool
    {
        $dim = $target->dim;

        if ($dim === null) {
            return false;
        }

        // A key checked against a list the code knows carries only what the
        // check leaves possible, as a value would.
        $taint = self::guarded($this->state->effectiveTaintOf($dim), $this->proofFor($dim, $this->currentBlock));

        return $this->state->addShape(
            $target->var,
            Shape::keys($taint),
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf('Used as a key of %s.', OperandHelper::describe($target->var)),
                [$dim],
            ),
        );
    }

    /**
     * `$arr['k'] = $v` and `$obj->p = $v` both assign to the *result temporary
     * of a fetch*, not to the base operand, and a later read produces a fresh
     * temporary with no SSA link back. Both therefore need explicit handling.
     *
     * `$taint` is what an element write stores, and `$value` the whole value
     * a property write stores.
     */
    private function propagateIndirectWrite(
        Op\Expr\Assign|Op\Expr\AssignRef $op,
        TaintSet $taint,
        Shape $value,
    ): bool {
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

                // Only when something reached it, and with what did. A probe
                // run seeds one parameter with every kind, so the kinds here
                // are the ones the body lets through to the property, plus any
                // its own sources add. The caller publishes the first of
                // those only: see applySummaryProperties().
                $this->recordPropertyReference($owner, $property, $value);

                // Whether the written value carried a literal fragment, so a
                // read elsewhere can tell `$this->option_name` holding
                // `'acme_' . $id` from one holding the request verbatim.
                // Recorded on every write, clean ones included: an anchor is a
                // property of the value, not of its taint.
                $this->properties->recordAnchor($owner, $property, $this->anchors->has($op->expr));
            }
        }

        // A computed key carries its own taint, and that is the key's, not an
        // element's: `$seen[ $_POST['name'] ] = true` makes a key of request
        // data and a value of `true`. Recorded whatever the value holds.
        $keyed = $target instanceof Op\Expr\ArrayDimFetch
            && $target->dim !== null
            && OperandHelper::literalKey($target->dim) === null
            && $this->recordKeyTaint($op, $target);

        if ($target instanceof Op\Expr\PropertyFetch || $target instanceof Op\Expr\StaticPropertyFetch) {
            return $this->writeProperty($op, $target, $value);
        }

        if ($taint->isEmpty()) {
            return $keyed;
        }

        if ($target instanceof Op\Expr\ArrayDimFetch) {
            $key = $target->dim === null ? null : OperandHelper::literalKey($target->dim);

            // A literal key is precise, and a read naming the same key sees
            // only this. `$context['id'] = 42` no longer taints
            // `$context['title']`.
            if ($key !== null) {
                return $this->state->addShape(
                    $target->var,
                    Shape::element($key, Shape::of($taint)),
                    new Provenance(
                        TraceVerb::Propagate,
                        $op,
                        sprintf("Written into %s['%s'].", OperandHelper::describe($target->var), $key),
                        [$op->expr],
                    ),
                );
            }

            // A probe's write under the key of a loop over its parameter puts
            // what each element brought under Shape::EACH: see eachPart().
            $each = $target->dim === null ? null : $this->eachPart($target->dim);

            if ($each !== null) {
                return $this->writeEachElement($op, $target, $taint, $each) || $keyed;
            }

            // A write under the key of a loop over an array with literal keys
            // puts each element's kinds back under that element's key: see
            // rebuildLoopNumbers().
            $numbers = $target->dim === null ? null : $this->loopKeyNumbers($target->dim);

            if ($numbers !== null && $taint->namesElements()) {
                return $this->writeUnderLoopKeys($op, $target, $taint, $numbers) || $keyed;
            }


            // A computed key can land anywhere, so it goes to the whole-array
            // slot — which is what every element write did before.
            //
            // Held apart from the operand's own taint because SSA does not
            // re-version an array for an element write: `$a = array();` and
            // `$a[$k] = $tainted;` write the same operand, and letting them
            // share a slot makes the fixed point oscillate.
            return $this->state->addShape(
                $target->var,
                Shape::rest(Shape::of($taint)),
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
            ) || $keyed;
        }

        return false;
    }

    /**
     * A write of the whole value `$value` into a property.
     */
    private function writeProperty(
        Op\Expr\Assign|Op\Expr\AssignRef $op,
        Op\Expr\PropertyFetch|Op\Expr\StaticPropertyFetch $target,
        Shape $value,
    ): bool {
        if ($value->isEmpty()) {
            return false;
        }

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
            $value,
            $this->writeTrace($op, $property, $value->flatten()),
        );
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

        // `$request['id']` is `$request->get_param( 'id' )`: WP_REST_Request
        // implements ArrayAccess over the same parameters. It was not a source
        // at all, so the commonest way to read a REST parameter reached a sink
        // as a parameter of unknown origin, at low.
        if ($this->isRestRequest($op->var)) {
            $read = $this->transferRestParameter($op, $op->var, is_string($key) ? $key : null, sprintf(
                '%s[%s] is a REST request parameter, which is user-supplied data.',
                OperandHelper::describe($op->var),
                is_string($key) ? "'" . $key . "'" : '…',
            ));

            if ($read !== null) {
                return $read;
            }
        }

        if ($this->readsUntaintedSubKey($op, $key)) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        $overwrite = $key === null ? null : $this->overwriteBefore($op, $key);

        if ($overwrite !== null && $key !== null) {
            return $this->transferOverwrittenRead($op, $key, $overwrite);
        }

        if ($key !== null) {
            return $this->transferKeyedRead($op, [$key]);
        }

        // A key the resolver names every value of reads only those elements.
        $named = $op->dim === null ? null : $this->namedKeys($op->dim);

        if ($named !== null) {
            return $this->transferKeyedRead($op, $named);
        }

        return $this->transferContainerRead(
            $op,
            $op->var,
            sprintf('Read out of %s.', OperandHelper::describe($op->var)),
        );
    }

    /**
     * The write that last set this element, earlier in the same block, when
     * nothing between could have changed it.
     *
     * php-cfg keeps one operand for an array however many of its elements are
     * written, so a write under a key joins the element it replaces:
     *
     * ```php
     * $args['include'] = implode( ',', wp_parse_id_list( $args['include'] ) );
     * $include         = 'AND webhook_id IN (' . $args['include'] . ')';
     * ```
     *
     * read the request's list, which the first line had replaced with ids.
     * Within one block the ops run in order, so the read sees exactly what
     * the write left. Anything between that touches the array, other than a
     * read or write under a different literal key, ends the search: a write
     * under a computed key, a push that could land on an integer key, a call
     * the array is handed to, an `unset()`. So does an array that can change
     * without its operand in sight: one a reference, a `global`, a `static` or
     * a by-reference capture binds. See {@see referencedNames()}.
     */
    private function overwriteBefore(Op\Expr\ArrayDimFetch $read, int|string $key): ?Op\Expr\Assign
    {
        $block = $this->currentBlock;
        $array = $read->var;

        $name = OperandHelper::variableName($array);
        $referenced = $this->referencedNames();

        if ($block === null || $name === 'GLOBALS' || $referenced === null || isset($referenced[$name ?? ''])) {
            return null;
        }

        $children = array_values($block->children);
        $at = self::positionOf($read, $children);

        if ($at === null) {
            return null;
        }

        // Back from the read, nearest first.
        foreach (array_reverse(array_slice($children, 0, $at, true), true) as $index => $op) {
            if (! in_array($op, $array->usages, true)) {
                continue;
            }

            if (! $op instanceof Op\Expr\ArrayDimFetch || $op->var !== $array) {
                return null;
            }

            if ($op->dim === null) {
                // A push takes the next integer key, which could be this one.
                if (is_int($key)) {
                    return null;
                }

                continue;
            }

            $written = OperandHelper::literalKey($op->dim);

            if ($written === null) {
                return null;
            }

            if ($written !== $key) {
                continue;
            }

            // The same element: the write that set it, or a read of it or a
            // write below it, which ends the search.
            foreach ($op->result->ops as $writer) {
                if ($writer instanceof Op\Expr\Assign && $writer->var === $op->result) {
                    $position = self::positionOf($writer, $children);

                    return $position !== null && $position > $index && $position < $at ? $writer : null;
                }
            }

            return null;
        }

        return null;
    }

    /**
     * @param list<Op> $ops
     */
    private static function positionOf(Op $op, array $ops): ?int
    {
        foreach ($ops as $position => $each) {
            if ($each === $op) {
                return $position;
            }
        }

        return null;
    }

    /**
     * The variables in this function that can change without an op on their
     * operand, by name, or null when any of them can: see
     * {@see overwriteBefore()}.
     *
     * A reference binds the variables on both sides, a `global` or `static`
     * the one it names, a by-reference loop its collection and value, and a
     * closure the variables it captures by reference. Only an include,
     * `eval`, `extract()`, `parse_str()` or a variable variable can change a
     * variable the code never names, so only those give up on every one.
     *
     * @return array<string, true>|null
     */
    private function referencedNames(): ?array
    {
        if ($this->referencedNamesFound) {
            return $this->referencedNames;
        }

        $this->referencedNamesFound = true;
        $names = [];

        foreach ($this->context->func->params as $param) {
            if ($param->byRef) {
                $names[] = OperandHelper::variableName($param->result);
            }
        }

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (
                    $op instanceof Op\Expr\Include_
                    || $op instanceof Op\Expr\Eval_
                    || $op instanceof Op\Expr\VarVar
                ) {
                    return $this->referencedNames = null;
                }

                if ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall) {
                    $name = OperandHelper::literalString($op->name);

                    if ($name !== null && in_array(strtolower(ltrim($name, '\\')), ['extract', 'parse_str'], true)) {
                        return $this->referencedNames = null;
                    }
                }

                if ($op instanceof Op\Expr\AssignRef) {
                    $names[] = self::baseName($op->var);
                    $names[] = self::baseName($op->expr);
                }

                if ($op instanceof Op\Terminal\GlobalVar || $op instanceof Op\Terminal\StaticVar) {
                    $names[] = OperandHelper::variableName($op->var) ?? OperandHelper::literalString($op->var);
                }

                if ($op instanceof Op\Iterator\Value && $op->byRef) {
                    $names[] = self::baseName($op->var);
                    $names[] = OperandHelper::variableName($op->result);
                }

                if ($op instanceof Op\Expr\Closure) {
                    foreach ($op->useVars as $use) {
                        if ($use instanceof Operand\BoundVariable && $use->byRef) {
                            $names[] = OperandHelper::literalString($use->name);
                        }
                    }
                }
            }
        }

        $this->referencedNames = [];

        foreach ($names as $name) {
            if ($name !== null) {
                $this->referencedNames[$name] = true;
            }
        }

        return $this->referencedNames;
    }

    /**
     * The variable an operand is, or the one it is an element or property
     * of: `$args` for `$args['k']['j']`.
     */
    private static function baseName(Operand $operand): ?string
    {
        for ($hops = 0; $hops < Shape::DEPTH + 2; $hops++) {
            $name = OperandHelper::variableName($operand);

            if ($name !== null) {
                return $name;
            }

            $definition = OperandHelper::definingOp($operand);

            if (! $definition instanceof Op\Expr\ArrayDimFetch && ! $definition instanceof Op\Expr\PropertyFetch) {
                return null;
            }

            $operand = $definition->var;
        }

        return null;
    }

    /**
     * A read of an element the same block wrote earlier: what the write left.
     */
    private function transferOverwrittenRead(Op\Expr\ArrayDimFetch $op, int|string $key, Op\Expr\Assign $write): bool
    {
        $value = $write->expr;
        $proof = $this->proofFor($value, $this->currentBlock);
        $taint = self::guarded($this->state->taintOf($value), $proof);
        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf(
                "Read out of %s['%s'], as the write on line %d left it.",
                OperandHelper::describe($op->var),
                $key,
                $write->getLine(),
            ),
            [$value],
        );
        $changed = $proof === null && $this->state->addShape($op->result, $this->state->shapeOf($value), $provenance);

        return $this->state->set($op->result, $taint, $taint->isEmpty() ? null : $provenance) || $changed;
    }

    /**
     * A REST parameter read, narrowed by the route's schema where one applies.
     *
     * The schema applies only to the request WordPress hands a route's
     * callback, read in that callback. Anywhere else nothing says which route
     * the request came through, so the parameter is read as it arrives.
     *
     * Null when the catalogue has no REST source to read it as.
     */
    private function transferRestParameter(Op\Expr $op, Operand $request, ?string $name, string $description): ?bool
    {
        $source = $this->registry->source(Matcher::method('WP_REST_Request', 'get_param'));

        if ($source === null) {
            return null;
        }

        $kinds = $source->kinds;

        if ($name !== null && $this->isRouteRequest($request) && $this->restRoutes !== null) {
            $routes = $this->restRoutes->routesFor($this->context->key);

            if ($this->restRoutes->admitsOnlyFromList($routes, $name)) {
                // One of a fixed list of literals, which carries no payload,
                // though it can still name somebody else's row.
                $kinds = $kinds->intersect(TaintSet::of(TaintKind::ObjectId));
                $description .= sprintf(
                    ' The route\'s permission callback lets a request through only when \'%s\' is one of a fixed '
                        . 'list, which leaves %s.',
                    $name,
                    $kinds->isEmpty() ? 'nothing' : $kinds->describe(),
                );
            } else {
                $sanitized = $this->restParameters->sanitize($kinds, $name, $routes);

                if (! $sanitized->equals($kinds)) {
                    $description .= sprintf(
                        ' The route\'s args schema sanitises \'%s\' before the callback runs, which leaves %s.',
                        $name,
                        $sanitized->isEmpty() ? 'nothing' : $sanitized->describe(),
                    );
                }

                $kinds = $sanitized;
            }
        }

        if ($kinds->isEmpty()) {
            return $this->writeResult($op->result, TaintSet::empty());
        }

        return $this->writeResult(
            $op->result,
            $kinds,
            new Provenance(TraceVerb::Source, $op, $description),
        );
    }

    /**
     * Whether an operand is a `WP_REST_Request`, by its declared type or
     * because it is the request a route's callback was handed.
     */
    private function isRestRequest(Operand $operand): bool
    {
        if ($this->isRouteRequest($operand)) {
            return true;
        }

        $class = $this->receivers->classOf($operand, $this->context, $this->types);

        if ($class === null) {
            return false;
        }

        return in_array('wp_rest_request', $this->functions->classHierarchy()->lookupOrder($class), true)
            || strtolower(ltrim($class, '\\')) === 'wp_rest_request';
    }

    /**
     * Whether an operand is the first parameter of a REST route's callback,
     * which WordPress fills with the route's request.
     */
    private function isRouteRequest(Operand $operand): bool
    {
        if ($this->restRoutes === null || ! $this->restRoutes->handles($this->context->key)) {
            return false;
        }

        $parameter = $this->context->func->params[0] ?? null;

        if (! $parameter instanceof Op\Expr\Param) {
            return false;
        }

        $name = OperandHelper::literalString($parameter->name);

        return $name !== null && OperandHelper::variableName($operand) === $name;
    }

    /**
     * Whether the caller is proved entitled here: by a check in this body, or
     * because this is a REST route's callback and WordPress only runs it once
     * the route's permission callback has entitled the caller.
     */
    private function callerIsEntitled(): bool
    {
        return $this->capabilityGuards->isEntitled($this->currentBlock)
            || ($this->restRoutes?->isEntitled($this->context->key) ?? false);
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
        return $this->everyBaseSkipsSubKey($op->var, is_string($key) ? $key : null, 0);
    }

    /**
     * Does every value this operand can hold trace to a superglobal entry
     * whose sub-key list says this key is not the attacker's?
     *
     * A phi is followed when *all* of its inputs qualify:
     *
     *     $file = empty( $_FILES['csv'] ) ? $_FILES['fallback'] : $_FILES['csv'];
     *     fopen( $file['tmp_name'], 'r' );
     *
     * Both branches are `$_FILES` entries and `tmp_name` is PHP's own path in
     * either, so the merge is as safe as each side. One branch that is not a
     * qualifying fetch — a parameter, a `$_POST` array — disqualifies the
     * whole phi, because the value could be that branch's.
     */
    private function everyBaseSkipsSubKey(Operand $operand, ?string $key, int $depth): bool
    {
        if ($depth > 4) {
            return false;
        }

        $base = $this->throughAssignments($operand);

        if ($base instanceof Op\Phi) {
            if ($base->vars === []) {
                return false;
            }

            foreach ($base->vars as $var) {
                if (! $var instanceof Operand || ! $this->everyBaseSkipsSubKey($var, $key, $depth + 1)) {
                    return false;
                }
            }

            return true;
        }

        if (! $base instanceof Op\Expr\ArrayDimFetch) {
            return false;
        }

        $superglobal = OperandHelper::variableName($base->var);

        if ($superglobal === null) {
            return false;
        }

        $source = $this->registry->source(Matcher::superglobal($superglobal));

        return $source !== null && ! $source->matchesSubKey($key);
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
     * it the first way, and the first real codebase it was pointed at
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
     * `$context['title']` — a read that names one constant key, or a few the
     * key could be.
     *
     * Sees what was written to those keys, plus whatever went in under a
     * computed key, because a computed write could have been this one. What
     * it does not see is another key's taint, which is the whole point.
     *
     * @param non-empty-list<int|string> $keys
     */
    private function transferKeyedRead(Op\Expr\ArrayDimFetch $op, array $keys): bool
    {
        // The element under the key, and the rest, since a write under a
        // computed key could have landed on this one. The value read out keeps
        // their parts as its own shape, so `$a['x']['y']` reads only what
        // `'y'` was given.
        $shape = $this->state->shapeOf($op->var);
        $element = Shape::empty();

        foreach ($keys as $each) {
            $element = $element->join($shape->elementAt($each));
        }

        $key = $keys[0];
        $rest = $shape->restPart();
        $fallback = $rest->own()->union($this->state->taintOf($op->var));
        $taint = $element->own()->union($fallback);

        $read = new Provenance(
            TraceVerb::Propagate,
            $op,
            count($keys) === 1
                ? sprintf("Read out of %s['%s'].", OperandHelper::describe($op->var), $key)
                : sprintf('Read out of %s under %s.', OperandHelper::describe($op->var), self::describeKeys($keys)),
            [$op->var],
        );
        $changed = $this->state->addShape($op->result, $element->join($rest)->structure(), $read);

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint) || $changed;
        }

        // When only the element carries the taint, the trace follows the
        // element: its write, or the call whose return put it there. The
        // array's own provenance says nothing about it, and following that
        // left a returned element's trace at "read out of" with no source.
        $written = $fallback->isEmpty() && count($keys) === 1
            ? $this->state->partProvenanceOf($op->var, $key)
            : null;

        return $this->state->set($op->result, $taint, $written ?? $read) || $changed;
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
            $this->rebuildLoopNumbers($op->var),
        );
    }

    /**
     * @param array<int|string, int>|null $numbers for a loop that rebuilds an array under its own key, the
     *                                             number each literal key's element is labelled with: see
     *                                             {@see TaintSet::fromElement()}
     */
    private function transferContainerRead(
        Op\Expr $op,
        Operand $container,
        string $description,
        ?array $numbers = null,
    ): bool {
        // A read out of a container sees every element: a computed key could
        // be any of them, and a `foreach` visits all of them. What they hold
        // below themselves stays apart, so `$row['title']` in a loop over
        // rows reads each row's title and not the whole row.
        $any = $this->state->shapeOf($container)->anyElement();
        $taint = $numbers === null
            ? $this->state->taintOf($container)->union($any->own())
            : $this->labelledLoopValue($container, $numbers);
        $read = new Provenance(TraceVerb::Propagate, $op, $description, [$container]);
        $changed = $this->state->addShape($op->result, $any->structure(), $read);

        if ($taint->isEmpty()) {
            return $this->state->set($op->result, $taint) || $changed;
        }

        $provenance = $this->state->taintOf($container)->isEmpty()
            ? $this->state->partProvenanceOf($container, null)
            : null;

        return $this->state->set($op->result, $taint, $provenance ?? $read) || $changed;
    }

    /**
     * A loop value's own taint with each literal key's element labelled by
     * its number, and what the collection carries as a whole or under a
     * computed key from anywhere. The same kinds as an unlabelled read.
     *
     * @param array<int|string, int> $numbers
     */
    private function labelledLoopValue(Operand $collection, array $numbers): TaintSet
    {
        $shape = $this->state->shapeOf($collection);
        $taint = $this->state->taintOf($collection)->union($shape->restPart()->own());

        foreach ($shape->elements() as $key => $element) {
            $own = $element->own();
            $taint = $taint->union(isset($numbers[$key]) ? $own->fromElement($numbers[$key]) : $own);
        }

        return $taint;
    }

    /**
     * Each literal key of the array a loop that rebuilds it is over, and the
     * number its element is labelled with. Null for any other loop.
     *
     * ```php
     * foreach ( $raw as $k => $v ) {
     *     $out[ $k ] = trim( $v );
     * }
     * ```
     *
     * rebuilds `$raw` key by key. The loop value carries a number for each
     * element of `$raw`, and the write under the loop's key puts each
     * element's kinds back under that element's key in `$out`. So a request
     * value under `name` stays under `name`. A loop gets numbers only when a
     * write under its key is in the function, and numbers are handed out
     * once per key and never reused, so a value from one loop written under
     * another loop's key goes to the computed-key slot, as it always did.
     *
     * @return array<int|string, int>|null
     */
    private function rebuildLoopNumbers(Operand $collection): ?array
    {
        $id = spl_object_id($collection);

        if (! isset($this->rebuildLoops()[$id])) {
            return null;
        }

        foreach (array_keys($this->state->shapeOf($collection)->elements()) as $key) {
            if (! isset($this->loopElementNumbers[$id][$key]) && $this->nextElementNumber < TaintSet::MAX_PARTS) {
                $this->loopElementNumbers[$id][$key] = $this->nextElementNumber++;
            }
        }

        return $this->loopElementNumbers[$id] ?? null;
    }

    /**
     * Whether `$operand` is the parameter this probe run seeds, or a copy of
     * it.
     */
    private function isSeededParameter(Operand $operand): bool
    {
        $param = $this->seedParameterIndex === null
            ? null
            : ($this->context->func->params[$this->seedParameterIndex] ?? null);

        if (! $param instanceof Op\Expr\Param) {
            return false;
        }

        // Through copies and checks: `if ( is_array( $var ) ) { foreach (
        // $var … ) }` iterates the checked value.
        for ($hops = 0; $hops < self::MAX_ASSIGNMENT_HOPS; $hops++) {
            if ($operand === $param->result) {
                return true;
            }

            $op = OperandHelper::definingOp($operand);

            if (! $op instanceof Op\Expr\Assign && ! $op instanceof Op\Expr\Assertion) {
                return false;
            }

            $operand = $op->expr;
        }

        return false;
    }

    /**
     * The numbers of the loop whose key `$dim` is, when that loop rebuilds an
     * array: see {@see rebuildLoopNumbers()}.
     *
     * @return array<int|string, int>|null
     */
    private function loopKeyNumbers(Operand $dim): ?array
    {
        $collection = self::loopKeyCollection($dim);

        return $collection === null ? null : ($this->loopElementNumbers[spl_object_id($collection)] ?? null);
    }

    /**
     * The collection a loop is over, when `$dim` is that loop's key, through
     * any copies.
     */
    private static function loopKeyCollection(Operand $dim): ?Operand
    {
        $operand = $dim;

        for ($hops = 0; $hops < self::MAX_ASSIGNMENT_HOPS; $hops++) {
            $op = OperandHelper::definingOp($operand);

            if ($op instanceof Op\Iterator\Key) {
                return $op->var;
            }

            if (! $op instanceof Op\Expr\Assign) {
                return null;
            }

            $operand = $op->expr;
        }

        return null;
    }

    /**
     * The collections of this function's loops that a write under the loop's
     * own key rebuilds, by object id. Found once, from the graph.
     *
     * @return array<int, true>
     */
    private function rebuildLoops(): array
    {
        if ($this->rebuildLoops !== null) {
            return $this->rebuildLoops;
        }

        $this->rebuildLoops = [];

        foreach ($this->blocks as $block) {
            foreach ($block->children as $op) {
                if (
                    ! $op instanceof Op\Expr\ArrayDimFetch
                    || $op->dim === null
                    || ! OperandHelper::isWrittenElsewhere($op->result, $op)
                ) {
                    continue;
                }

                $collection = self::loopKeyCollection($op->dim);

                if ($collection !== null) {
                    $this->rebuildLoops[spl_object_id($collection)] = true;
                }
            }
        }

        return $this->rebuildLoops;
    }

    /**
     * The parts of the seeded parameter a loop over it reads each element
     * through, when `$dim` is that loop's key: `[*]`, and `[others]` when the
     * body names some of its keys.
     *
     * The parameter's elements are its callers', so the probe cannot name
     * their keys. But what those parts bring to a write under the loop's key
     * is each element coming back under the key it had, and the summary says
     * so: see {@see Shape::EACH}.
     *
     * @return non-empty-list<int>|null
     */
    private function eachPart(Operand $dim): ?array
    {
        $collection = self::loopKeyCollection($dim);

        if ($collection === null || ! $this->isSeededParameter($collection)) {
            return null;
        }

        $any = null;
        $parts = [];

        foreach ($this->seedParts as $position => $path) {
            if ($path === [ParameterParts::ANY]) {
                $any = $position + 1;
            } elseif ($path === [ParameterParts::OTHERS]) {
                $parts[] = $position + 1;
            }
        }

        return $any === null ? null : [$any, ...$parts];
    }

    /**
     * Write `$taint` under the key of a loop over the seeded parameter: what
     * `$parts` brought under {@see Shape::EACH}, and the rest under a
     * computed key.
     *
     * @param non-empty-list<int> $parts
     */
    private function writeEachElement(
        Op\Expr\Assign|Op\Expr\AssignRef $op,
        Op\Expr\ArrayDimFetch $target,
        TaintSet $taint,
        array $parts,
    ): bool {
        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf('Written into %s under the key it came from.', OperandHelper::describe($target->var)),
            [$op->expr],
        );
        $each = TaintSet::empty();
        $rest = $taint;

        foreach ($parts as $part) {
            $each = $each->union($taint->onlyPart($part));
            $rest = $rest->exceptPart($part);
        }

        $changed = ! $each->isEmpty()
            && $this->state->addShape($target->var, Shape::element(Shape::EACH, Shape::of($each)), $provenance);

        if ($rest->isEmpty()) {
            return $changed;
        }

        return $this->state->addShape($target->var, Shape::rest(Shape::of($rest)), $provenance) || $changed;
    }

    /**
     * The keys a computed key can hold, when the resolver names every one of
     * them: a constant, a join of literals, a `foreach` over a literal array.
     * Null when it cannot. Found once per operand, since it depends on the
     * code and not on the taint.
     *
     * @return non-empty-list<int|string>|null
     */
    private function namedKeys(Operand $dim): ?array
    {
        $id = spl_object_id($dim);

        if (array_key_exists($id, $this->namedKeys)) {
            return $this->namedKeys[$id];
        }

        $literal = OperandHelper::literalKey($dim);

        if ($literal !== null) {
            return $this->namedKeys[$id] = [$literal];
        }

        $keys = [];

        // As PHP stores them: `'1'` is `1`.
        foreach ($this->resolver->values()->keyStrings($dim) as $string) {
            $keys[array_key_first([$string => true])] = true;
        }

        return $this->namedKeys[$id] = $keys === [] ? null : array_keys($keys);
    }

    /**
     * `'path'`, or `one of 'path', 'tmpPath'`, for a trace.
     *
     * @param list<int|string> $keys
     */
    private static function describeKeys(array $keys): string
    {
        $quoted = array_map(static fn (int|string $key): string => "'" . $key . "'", $keys);

        return count($quoted) === 1 ? $quoted[0] : 'one of ' . implode(', ', $quoted);
    }

    /**
     * Write `$taint` under a loop's key: each element's kinds under that
     * element's key, and whatever came from elsewhere under a computed key.
     *
     * @param array<int|string, int> $numbers
     */
    private function writeUnderLoopKeys(
        Op\Expr\Assign|Op\Expr\AssignRef $op,
        Op\Expr\ArrayDimFetch $target,
        TaintSet $taint,
        array $numbers,
    ): bool {
        $changed = false;
        $all = 0;

        foreach ($numbers as $key => $number) {
            $all |= 1 << $number;
            $piece = $taint->forElement($number);

            if ($piece->isEmpty()) {
                continue;
            }

            $changed = $this->state->addShape(
                $target->var,
                Shape::element($key, Shape::of($piece)),
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf(
                        "Written into %s['%s'], the key it came from.",
                        OperandHelper::describe($target->var),
                        $key,
                    ),
                    [$op->expr],
                ),
            ) || $changed;
        }

        $elsewhere = $taint->beyondElements($all);

        if ($elsewhere->isEmpty()) {
            return $changed;
        }

        return $this->state->addShape(
            $target->var,
            Shape::rest(Shape::of($elsewhere)),
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
        ) || $changed;
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

        $stored = $this->storedPropertyValue($owner, $property);
        $taint = $stored->own()->union($this->state->taintOf($op->var));

        if ($taint->isEmpty() && $stored->isEmpty()) {
            return $this->state->set($op->result, $taint);
        }

        return $this->readProperty($op, $owner, $property, $taint, $stored, [$op->var]);
    }

    /**
     * Put a property's value on the fetch that reads it: its own taint, and
     * its elements under their keys.
     *
     * @param list<Operand> $from
     */
    private function readProperty(
        Op\Expr\PropertyFetch|Op\Expr\StaticPropertyFetch $op,
        ?string $owner,
        string $property,
        TaintSet $taint,
        Shape $stored,
        array $from,
    ): bool {
        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf(
                $op instanceof Op\Expr\PropertyFetch ? 'Read from property $%s.' : 'Read from static property $%s.',
                $property,
            ),
            $from,
            prefix: $this->storedPropertyOrigin($owner, $property),
        );

        $changed = $this->state->set($op->result, $taint, $taint->isEmpty() ? null : $provenance);
        $id = spl_object_id($op);

        // Elements only ever grow, so a value this read already put on its
        // result adds nothing when it comes back unchanged.
        if (($this->propertyReads[$id] ?? null) !== $stored) {
            $changed = $this->state->addShape($op->result, $stored->structure(), $provenance) || $changed;
            $this->propertyReads[$id] = $stored;
        }

        return $changed;
    }

    /**
     * The stored taint of a property, unioned across the class hierarchy.
     *
     * A write lands under the class whose method performed it: the parent's
     * constructor writes under the parent, an override under the child. The
     * property is one storage slot on the instance regardless, so a read has
     * to see every ancestor's writes or a flow through an inherited property
     * disappears — `$this->value = $_GET['x']` in a base-class constructor,
     * echoed by a subclass method, was invisible under flat keys.
     */
    private function storedPropertyValue(?string $owner, string $property): Shape
    {
        if ($owner === null) {
            return $this->properties->valueOf(null, $property);
        }

        $values = [];

        foreach ($this->functions->classHierarchy()->lookupOrder($owner) as $candidate) {
            $values[] = $this->properties->valueOf($candidate, $property);
        }

        $key = strtolower($owner) . '::' . $property;
        $memo = $this->storedValues[$key] ?? null;

        if ($memo !== null && $memo[0] === $values) {
            return $memo[1];
        }

        $value = Shape::empty();

        foreach ($values as $each) {
            $value = $value->join($each);
        }

        $this->storedValues[$key] = [$values, $value];

        return $value;
    }

    /**
     * The recorded origin of the nearest class in the hierarchy that tracked
     * the property, so the trace still says where the value was written.
     *
     * @return list<TraceStep>
     */
    private function storedPropertyOrigin(?string $owner, string $property): array
    {
        foreach ($owner === null ? [null] : $this->functions->classHierarchy()->lookupOrder($owner) as $candidate) {
            if ($this->properties->isTracked($candidate, $property)) {
                return $this->properties->originOf($candidate, $property);
            }
        }

        return [];
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
        // A static property not redeclared by the subclass is the parent's one
        // slot, so `Child::$option` and `Base::$option` are the same storage —
        // the union across the hierarchy applies exactly as it does to
        // instance properties.
        $stored = $this->storedPropertyValue($owner, $property);

        if ($stored->isEmpty()) {
            return $this->state->set($op->result, TaintSet::empty());
        }

        return $this->readProperty($op, $owner, $property, $stored->own(), $stored, []);
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
        return $this->receivers->propertyOwnerOf($fetch->var, $this->context, $this->types);
    }

    private function transferConcatList(Op\Expr\ConcatList $op): bool
    {
        $parts = [];

        foreach ($op->list as $item) {
            if ($item instanceof Operand) {
                $parts[] = $item;
            }
        }

        return $this->transferConcatenation(
            $op,
            $parts,
            'Interpolated into a string. Interpolation concatenates; it does not escape.',
        );
    }

    private function transferBinaryConcat(Op\Expr\BinaryOp $op): bool
    {
        if ($op instanceof Op\Expr\BinaryOp\Coalesce) {
            return $this->transferUnion(
                $op,
                [$op->left, $op->right],
                'Null coalescing passes the left-hand value through when it is set.',
            );
        }

        return $this->transferConcatenation($op, [$op->left, $op->right], 'Concatenated into a larger string.');
    }

    /**
     * A concatenation: the union of its parts, with an escaped SQL value moved
     * to where its quotes put it. See {@see SqlQuoteFold}.
     *
     * The fold reads the whole string this one belongs to, through the
     * concatenations and assignments that built it, so `"x = '" . esc_sql( $v )
     * . "'"` sees both quotes although PHP builds it in two steps.
     *
     * @param list<Operand> $inputs
     */
    private function transferConcatenation(Op\Expr $op, array $inputs, string $description): bool
    {
        // Each part is written whole, as text. `implode()` hands back its
        // elements' taint as a container, and elements escaped and joined
        // between quotes this concatenation writes are quoted here too:
        // `"NOT IN ('" . implode( "', '", array_map( 'esc_sql', $a ) ) . "')"`.
        $direct = array_map(fn (Operand $input): TaintSet => $this->guardedEffectiveTaintOf($input), $inputs);

        if (! SqlQuoteFold::applies($direct)) {
            return $this->transferUnion($op, $inputs, $description);
        }

        $parts = $this->queryShapes->parts($op->result);

        if ($parts === null) {
            return $this->transferUnion($op, $inputs, $description);
        }

        $taint = SqlQuoteFold::fold(array_map(
            fn (array $part): array => [$part[1], $this->guardedEffectiveTaintOf($part[0])],
            $parts,
        ));

        return $this->writeResult(
            $op->result,
            $taint,
            $taint->isEmpty() ? null : new Provenance(TraceVerb::Propagate, $op, $description, $inputs),
        );
    }

    /**
     * What a function that can undo escaping leaves of a value: its escaped
     * SQL residuals as raw `sql` again, and a formula behind an apostrophe as
     * a formula, since `substr( $v, 1 )` takes the apostrophe off.
     *
     * A probe run notes that it happened to SQL-carrying data, so the summary
     * can say a caller's escaped argument may come back unescaped. See
     * {@see FunctionSummary::$revertsResiduals}.
     */
    private function undoneEscaping(TaintSet $taint): TaintSet
    {
        $this->noteReverted(self::residuals(), $taint);

        return self::unescaped($taint);
    }

    /**
     * Record, in a probe run, that residuals may have been undone on the
     * seeded parameter's own data, when it carries the kind they qualify.
     * Other request data in the body says nothing about the parameter: see
     * {@see TaintKind::Seed}.
     */
    private function noteReverted(TaintSet $residuals, TaintSet $taint): void
    {
        if (! $this->collecting || $this->seedParameterIndex === null || $residuals->isEmpty()) {
            return;
        }

        if (! $taint->has(TaintKind::Seed)) {
            return;
        }

        $noted = $taint->has(TaintKind::Sql) ? $residuals->intersect(self::sqlResiduals()) : TaintSet::empty();

        if ($taint->has(TaintKind::Csv) && $residuals->has(TaintKind::CsvPrefixed)) {
            $noted = $noted->with(TaintKind::CsvPrefixed);
        }

        if ($noted->isEmpty()) {
            return;
        }

        $this->revertedResiduals = ($this->revertedResiduals ?? TaintSet::empty())->union($noted);
    }

    /**
     * Every kind an escaper leaves that a later function can undo.
     */
    private static function residuals(): TaintSet
    {
        /** @var TaintSet|null $residuals */
        static $residuals = null;

        return $residuals ??= self::sqlResiduals()->with(TaintKind::CsvPrefixed);
    }

    private static function sqlResiduals(): TaintSet
    {
        /** @var TaintSet|null $residuals */
        static $residuals = null;

        return $residuals ??= TaintSet::of(TaintKind::SqlUnquoted, TaintKind::SqlSelfQuoted, TaintKind::SqlUnticked);
    }

    /**
     * An escaped SQL value's residuals turned back into `sql`, and
     * `csv_prefixed` back into `csv`.
     */
    private static function unescaped(TaintSet $taint): TaintSet
    {
        $residuals = self::sqlResiduals();

        if (! $taint->intersect($residuals)->isEmpty()) {
            $taint = $taint->without($residuals)->with(TaintKind::Sql);
        }

        return $taint->has(TaintKind::CsvPrefixed)
            ? $taint->without(TaintSet::of(TaintKind::CsvPrefixed))->with(TaintKind::Csv)
            : $taint;
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
            // The whole value, parts and all, so an array nested in a literal
            // keeps its own elements apart.
            $shape = $this->state->valueShapeOf($value);

            if ($shape->isEmpty()) {
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

            $changed = $this->state->addShape(
                $op->result,
                Shape::element($key, $shape),
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf("Placed into an array literal under '%s'.", $key),
                    [$value],
                ),
            ) || $changed;
        }

        $rest = Shape::empty();

        foreach ($unkeyed as $value) {
            $rest = $rest->join($this->state->valueShapeOf($value));
        }

        if ($rest->isEmpty()) {
            return $changed;
        }

        return $this->state->addShape(
            $op->result,
            Shape::rest($rest),
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
     * An element under a literal key is an element too. Leaving it out lost
     * `implode( ',', array( 'k' => $_GET['v'] ) )` entirely. When the result
     * has no keys to keep it under, it joins the others. When the result keeps
     * its input's keys, `array_filter()` or `apply_filters()` on an array, an
     * element under a string key stays under that key: folding it in made a
     * stored `'value'` taint the `'id'` read beside it. A result that keeps
     * its input's values, `array_values()`, holds each of them under a
     * computed key.
     *
     * Either way each element keeps what it holds below itself when the call
     * is `$direct`: its inputs are the arrays the function is handed, and its
     * result is what the function returns. A guard or an escaping change on
     * the value reads it as one set.
     *
     * @param list<Operand> $inputs
     */
    private function transferUnion(
        Op\Expr $op,
        array $inputs,
        string $description,
        bool $imprecise = false,
        bool $keepsKeys = false,
        bool $revertResiduals = false,
        ?TaintKind $sqlBecomes = null,
        bool $keepsValues = false,
        bool $direct = false,
    ): bool {
        $taint = TaintSet::empty();
        $container = TaintSet::empty();
        $keys = TaintSet::empty();

        // An array result keeps each element whole, and anything else, a
        // string, folds its elements into one set.
        $whole = $direct && ($keepsKeys || $keepsValues) && ! $revertResiduals && $sqlBecomes === null;
        $rest = Shape::empty();

        /** @var list<array{0: Operand, 1: string, 2: TaintSet, 3: Shape}> $kept */
        $kept = [];

        // A guarded input brings only what the guard admits, so
        // `'ORDER BY ' . $orderby` behind an allowlist check on $orderby
        // builds a query from a listed value.
        foreach ($inputs as $input) {
            if ($input === null) {
                continue;
            }

            $proof = $this->proofFor($input, $this->currentBlock);
            $shape = $this->state->shapeOf($input);
            $keepsWhole = $whole && $proof === null;
            $taint = $taint->union(self::guarded($this->state->taintOf($input), $proof));

            if ($keepsWhole) {
                $rest = $rest->join($shape->restPart());
            } else {
                $container = $container->union(self::guarded($shape->restPart()->flatten(), $proof));
            }

            // A result that keeps its input's keys keeps what they carry.
            if ($keepsKeys) {
                $keys = $keys->union(self::guarded($shape->keysTaint(), $proof));
            }

            foreach ($shape->elements() as $key => $element) {
                $keyed = $element->flatten();

                if ($keepsKeys && is_string($key)) {
                    $kept[] = [$input, $key, self::guarded($keyed, $proof), $keepsWhole ? $element : Shape::empty()];

                    continue;
                }

                if ($keepsWhole) {
                    $rest = $rest->join($element);
                } else {
                    $container = $container->union(self::guarded($keyed, $proof));
                }
            }
        }

        // A function that can undo an escaper's work leaves an escaped SQL
        // value as raw as it was: `stripslashes( esc_sql( $v ) )`.
        if ($revertResiduals) {
            $taint = $this->undoneEscaping($taint);
            $container = $this->undoneEscaping($container);
            $kept = array_map(
                fn (array $entry): array => [$entry[0], $entry[1], $this->undoneEscaping($entry[2]), $entry[3]],
                $kept,
            );
        }

        // An escaper written as a replacement: `sql` becomes the residual it
        // leaves. See escapeReading().
        if ($sqlBecomes !== null) {
            $escaped = static fn (TaintSet $set): TaintSet => $set->has(TaintKind::Sql)
                ? $set->without(TaintSet::of(TaintKind::Sql))->with($sqlBecomes)
                : $set;
            $taint = $escaped($taint);
            $container = $escaped($container);
            $kept = array_map(
                static fn (array $entry): array => [$entry[0], $entry[1], $escaped($entry[2]), $entry[3]],
                $kept,
            );
        }

        $hasKept = array_filter($kept, static fn (array $entry): bool => ! $entry[2]->isEmpty()) !== [];

        $provenance = $taint->isEmpty() && $container->isEmpty() && $rest->isEmpty() && $keys->isEmpty() && ! $hasKept
            ? null
            : new Provenance(TraceVerb::Propagate, $op, $description, $inputs, imprecise: $imprecise);

        // A result that keeps its inputs' keys keeps each element's markers
        // with the element, so the call's own `escaped` is only theirs.
        $changed = $this->writeResult($op->result, $taint, $provenance, $keepsKeys ? $inputs : []);

        if ($provenance === null) {
            return $changed;
        }

        // What the inputs hold under a computed key: whole where the result
        // keeps it whole, see $whole, and as one set from an input a guard
        // vouched for or a result that is not an array. A trace goes through
        // this call on its way to the writes below.
        $computed = $rest->join(Shape::of($container));
        $computed = Shape::node($computed->own(), $computed->structure(), $provenance);

        if (! $computed->isEmpty()) {
            $changed = $this->state->addShape($op->result, Shape::rest($computed), $provenance) || $changed;
        }

        if (! $keys->isEmpty()) {
            $changed = $this->state->addShape($op->result, Shape::keys($keys), $provenance) || $changed;
        }

        foreach ($kept as [$input, $key, $keyed, $element]) {
            if ($keyed->isEmpty()) {
                continue;
            }

            $changed = $this->state->addShape(
                $op->result,
                Shape::element($key, $element->isEmpty() ? Shape::of($keyed) : $element),
                $this->state->partProvenanceOf($input, $key) ?? $provenance,
            ) || $changed;
        }

        return $changed;
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

        // Not an array on this branch: the value holds no elements, and what
        // it carries is its own taint. See AssertionNarrowing::provesNotArray().
        if (AssertionNarrowing::provesNotArray($op)) {
            $taint = self::guarded($this->state->taintOf($op->expr), $this->proofFor($op->expr, $this->currentBlock));

            return $this->writeResult(
                $op->result,
                $taint,
                $taint->isEmpty() ? null : new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    'A check proved this is not an array here, so it holds no elements.',
                    [$op->expr],
                ),
            );
        }

        if (! AssertionNarrowing::narrows($op)) {
            // The same value, checked: its parts are the value's, under the
            // keys they had. A pass-through folded them into a computed key,
            // so after `is_array( $settings )` every element read them all.
            $provenance = new Provenance(
                TraceVerb::Propagate,
                $op,
                'An isset() or empty() guard narrows the type but does not escape the value.',
                [$op->expr],
            );
            $taint = self::guarded($this->state->taintOf($op->expr), $this->proofFor($op->expr, $this->currentBlock));
            $changed = $this->writeResult($op->result, $taint, $taint->isEmpty() ? null : $provenance);

            return $this->state->addShape($op->result, $this->state->shapeOf($op->expr), $provenance) || $changed;
        }

        // A number carries no payload; it still names whichever row the
        // request chose, so the object-id kind survives the narrowing the way
        // it survives an int cast.
        return $this->writeResult(
            $op->result,
            $this->state->effectiveTaintOf($op->expr)->intersect(TaintSet::of(TaintKind::ObjectId)),
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
        //
        // What the probe run does instead is *record* which captures the seed
        // reached, exactly as it records property writes: the summary carries
        // "parameter reaches capture $name of closure key", and the call site
        // publishes the caller's actual taint. Without that, a capture whose
        // value is the enclosing function's own parameter was published clean
        // whatever the caller passed.
        if ($this->seedParameterIndex !== null) {
            $this->recordCaptureReferences($op);

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

    /**
     * A probe run reached a closure creation with the seeded parameter's taint
     * on a captured name. Recorded, not published — see {@see transferClosure}.
     */
    private function recordCaptureReferences(Op\Expr\Closure $op): void
    {
        $key = FunctionContext::keyFor($op->func, $this->context->file);
        $enclosing = $this->namedScopeWithOrigins();

        foreach ($op->useVars as $captured) {
            if (! $captured instanceof Operand) {
                continue;
            }

            $name = OperandHelper::variableName($captured);

            if ($name === null) {
                continue;
            }

            // A capture's record is one set: a closure's parameters are not
            // split into parts either.
            $taint = ($enclosing['taint'][$name] ?? Shape::empty())->flatten();

            if ($taint->isEmpty()) {
                continue;
            }

            $this->recordCaptureReference($key, $name, $taint);
        }
    }

    /**
     * Note that the seeded parameter reached a closure's capture, and with
     * what. See {@see FunctionSummary::$paramToCapture}.
     */
    private function recordCaptureReference(string $closureKey, string $name, TaintSet $taint): void
    {
        $id = $closureKey . '::' . $name;
        $kinds = ($this->capturesReached[$id][2] ?? TaintSet::empty())->union($taint);
        $this->capturesReached[$id] = [$closureKey, $name, $kinds];
    }

    /**
     * Keys, not values: `foreach ( $_GET as $k => $v )` has an
     * attacker-controlled key, but `foreach ( $rows as $k => $v )` after
     * `$rows[$i] = $tainted` does not. So the key takes the collection's own
     * taint and its keys', and none of its elements'.
     */
    private function transferIteratorKey(Op\Iterator\Key $op): bool
    {
        $taint = self::guarded(
            $this->keysOf($op->var),
            $this->proofFor($op->var, $this->currentBlock),
        );

        return $this->writeResult(
            $op->result,
            $taint,
            $taint->isEmpty() ? null : new Provenance(
                TraceVerb::Propagate,
                $op,
                'Keys of an attacker-controlled collection are attacker-controlled too.',
                [$op->var],
            ),
        );
    }

    /**
     * What an array's keys carry: its own taint, which every key inherits,
     * and what the computed keys written into it carried.
     */
    private function keysOf(Operand $array): TaintSet
    {
        return $this->state->taintOf($array)->union($this->state->shapeOf($array)->keysTaint());
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
        $proof = $this->proofFor($op->expr, $this->currentBlock);

        $taint = self::guarded($this->state->taintOf($op->expr), $proof);

        // The elements travel as elements, each under its key and to the
        // depth a shape keeps, and the keys as keys. Returning only the
        // value's own taint lost everything written into it: `$a['k'] =
        // $_GET['x']; return $a;` handed every caller a clean array. A guard's
        // proof is about the value as a whole, so a proven return keeps only
        // what the proof admits, under a computed key.
        $shape = $this->state->shapeOf($op->expr);
        $structure = $proof === null
            ? $shape->structure()
            : Shape::rest(Shape::of(self::guarded($shape->restPart()->flatten(), $proof)));

        $this->reportShortcodeReturn(
            $op,
            $op->expr,
            self::guarded($this->state->effectiveTaintOf($op->expr), $proof),
        );

        $merged = $this->returnTaint->union($taint);
        $changed = ! $merged->equals($this->returnTaint);
        $this->returnTaint = $merged;

        // A join that adds nothing hands back the shape it joined into.
        $merged = $this->returnShape->join($structure);
        $changed = $merged !== $this->returnShape || $changed;
        $this->returnShape = $merged;

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
        $previousWrites = $this->unionWrites;
        $this->unionResultWrites = true;
        $this->unionWrites = [];
        $changed = false;

        try {
            foreach ($calls as $call) {
                $this->resultMode = $call->resultMode;
                $changed = $this->transferCall($op, $call) || $changed;
            }

            $changed = $this->flushUnionWrites() || $changed;
        } finally {
            $this->unionResultWrites = $previousUnion;
            $this->resultMode = $previousMode;
            $this->unionWrites = $previousWrites;
        }

        return $changed;
    }

    /**
     * Apply the held-back result writes of a union of callees.
     *
     * Two things need every callee's write in hand before any of them lands.
     *
     * The first is the escape claim. Several callees are alternatives, exactly
     * like the branches a phi merges, so the rule in
     * {@see withoutSplitEscapeClaim()} applies here too. A hook dispatch is
     * where this matters:
     *
     *     add_filter( 'acme_label', 'esc_html' );
     *     echo apply_filters( 'acme_label', $_GET['a'] );
     *
     * The pass-through carries the raw request value and the voiding marker.
     * The `esc_html` callback carries the `escaped` marker. No single path
     * escaped the value and then filtered it, so the pair would report the
     * wrong defect: "escaping no longer holds", at medium severity, in place
     * of the raw value reaching output. `escaped` is dropped, as at a phi.
     *
     * The second is the trace. The state keeps one provenance per operand, and
     * the last write wins. The write carrying the most taint kinds goes last,
     * so the trace follows the path that carries the most kinds. Otherwise the
     * trace for the value above would run through `esc_html()`, which is not
     * how the raw value got out. This changes the trace only. The taint on the
     * operand is the same union whatever order the writes land in.
     */
    private function flushUnionWrites(): bool
    {
        $writes = $this->unionWrites;
        $this->unionWrites = [];

        if ($writes === []) {
            return false;
        }

        /** @var SplObjectStorage<Operand, list<TaintSet>> $byOperand */
        $byOperand = new SplObjectStorage();

        foreach ($writes as $write) {
            $byOperand[$write['operand']] = [...($byOperand[$write['operand']] ?? []), $write['taint']];
        }

        usort(
            $writes,
            static fn (array $a, array $b): int => self::payloadKinds($a['taint']) <=> self::payloadKinds($b['taint']),
        );

        $changed = false;

        foreach ($writes as $write) {
            $taint = self::withoutSplitCalleeClaim($write['taint'], $byOperand[$write['operand']]);
            $changed = $this->state->add($write['operand'], $taint, $write['provenance']) || $changed;
        }

        return $changed;
    }

    /**
     * {@see withoutSplitEscapeClaim()}, for the writes of a union of callees
     * rather than the operands of a phi.
     *
     * @param list<TaintSet> $alternatives
     */
    private static function withoutSplitCalleeClaim(TaintSet $taint, array $alternatives): TaintSet
    {
        if (! $taint->has(TaintKind::Escaped)) {
            return $taint;
        }

        $merged = TaintSet::empty();

        foreach ($alternatives as $alternative) {
            if ($alternative->has(TaintKind::Escaped) && $alternative->has(TaintKind::EscapeVoided)) {
                return $taint;
            }

            $merged = $merged->union($alternative);
        }

        return $merged->has(TaintKind::EscapeVoided)
            ? $taint->without(TaintSet::of(TaintKind::Escaped))
            : $taint;
    }

    /**
     * How many kinds a write carries, not counting the escaping markers.
     */
    private static function payloadKinds(TaintSet $taint): int
    {
        return count($taint->without(TaintSet::of(TaintKind::Escaped, TaintKind::EscapeVoided))->kinds());
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

    /**
     * @param list<Operand|null> $keptInputs arguments whose elements the result keeps under their own keys: see
     *                                       {@see voidEscaping()}
     */
    private function writeResult(
        Operand $result,
        TaintSet $taint,
        ?Provenance $provenance = null,
        array $keptInputs = [],
    ): bool {
        $voided = $this->voidEscaping($taint, $keptInputs);

        // Say where. A step describing the propagation is the wrong answer to
        // "filtered where?", and it was the only one in the trace. The prefix
        // survives the substitution: a stored read's trace still starts at the
        // write that stored the value, voided or not.
        if (! $voided->equals($taint)) {
            $provenance = $this->voidProvenance($voided, $provenance->prefix ?? []) ?? $provenance;
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
                : $this->state->addShape($result, Shape::rest(Shape::of($taint)), $provenance);
        }

        if (! $this->unionResultWrites) {
            return $this->state->set($result, $taint, $provenance);
        }

        if (! $taint->isEmpty()) {
            $this->unionWrites[] = ['operand' => $result, 'taint' => $taint, 'provenance' => $provenance];
        }

        // Reported as changed once every callee has been visited.
        return false;
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
        $changed = ($matcher === null ? false : $this->recordOptionWrite($op, $call, $matcher)) || $changed;

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
                if (
                    $op instanceof Op\Expr\MethodCall
                    && strtolower($matcher->key()) === 'method:wp_rest_request::get_param'
                    && $this->isRouteRequest($op->var)
                ) {
                    $name = OperandHelper::literalString($call->argument(0));
                    $read = $this->transferRestParameter($op, $op->var, $name, sprintf(
                        '%s returns user-supplied data.',
                        $matcher->describe(),
                    ));

                    if ($read !== null) {
                        return $read || $changed;
                    }
                }

                // A read of a key the scan watched being written carries the
                // write's taint and trace on top of the stored baseline — the
                // proven second-order flow, at the severity of what actually
                // went in, rather than the assumption that something might have.
                [$storedTaint, $storedOrigin] = $this->optionStoreTaint($matcher, $call);
                $kinds = $source->kinds->union($storedTaint);
                $description = sprintf(
                    '%s returns %s data.',
                    $matcher->describe(),
                    $source->stored ? 'stored, user-supplied' : 'user-supplied',
                );

                // `filter_input( INPUT_GET, 'id', FILTER_VALIDATE_INT )` reads
                // the request and filters it in one call.
                if ($source->filterArgument !== null) {
                    [$kinds, $proof, $filter] = $this->applyFilter(
                        $call,
                        $kinds,
                        $source->filterArgument,
                        $source->optionsArgument,
                    );
                    $description .= $proof === null
                        ? sprintf(' With %s, it comes back as it was.', $filter)
                        : sprintf(' With %s, it still carries %s.', $filter, $kinds->describe());
                }

                return $this->writeResult(
                    $op->result,
                    $kinds,
                    $kinds->isEmpty() ? null : new Provenance(
                        TraceVerb::Source,
                        $op,
                        $description,
                        prefix: $storedOrigin,
                    ),
                ) || $changed;
            }

            $propagator = $this->registry->propagator($matcher);

            if ($propagator !== null) {
                return $this->transferPropagator($op, $call, $propagator, $matcher) || $changed;
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

        $internal = $matcher === null ? null : $this->registry->internalFunction($matcher);

        if ($internal !== null) {
            return $this->transferInternalFunction($op, $call, $internal) || $changed;
        }

        // A named function nothing models, and not one of PHP's own. Returning
        // clean is the deliberate choice: a documented false negative beats an
        // undocumented false positive.
        return $this->writeResult($op->result, TaintSet::empty()) || $changed;
    }

    /**
     * One of PHP's own functions or methods that the catalogue does not model
     * by hand.
     *
     * Its declaration says what it returns. A result that can hold text holds
     * the text of the arguments that can: `explode( ',', $_GET['ids'] )`.
     * A call written with names or `...` cannot be matched to the declared
     * positions, so every argument counts.
     *
     * A method of one of PHP's classes that hold text also reads its object:
     * `$dom->saveHTML()` returns what `$dom->loadHTML( $html )` kept. And a
     * method that keeps its arguments puts them into the object, or into the
     * new object for `new ArrayObject( $_POST )`.
     */
    private function transferInternalFunction(Op\Expr $op, CallTarget $call, InternalFunction $internal): bool
    {
        $positions = $op->hasAttribute(CompatibilityVisitor::UNPACKED_OR_NAMED_ARGUMENTS)
            ? array_keys($call->arguments)
            : $internal->resolve($call->argumentCount());

        $inputs = [];

        foreach ($positions as $position) {
            $argument = $call->argument($position);

            if ($argument !== null) {
                $inputs[] = $argument;
            }
        }

        $name = $call->matcher?->describe() ?? $call->name();

        if ($op instanceof Op\Expr\New_) {
            if (! $internal->stores) {
                return $this->writeResult($op->result, TaintSet::empty());
            }

            return $this->transferUnion(
                $op,
                $inputs,
                sprintf('%s keeps its arguments, so the object holds them.', $name),
                revertResiduals: true,
            );
        }

        $changed = false;
        $receiver = $op instanceof Op\Expr\MethodCall ? $op->var : null;

        if ($internal->stores && $receiver !== null) {
            $kept = $this->undoneEscaping($this->state->unionOf($inputs));

            if (! $kept->isEmpty()) {
                $changed = $this->state->addShape($receiver, Shape::rest(Shape::of($kept)), new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf('%s keeps its arguments, so the object now holds %s.', $name, $kept->describe()),
                    $inputs,
                ));
            }
        }

        if (! $internal->returnsText) {
            return $this->writeResult($op->result, TaintSet::empty()) || $changed;
        }

        if ($internal->receiver && $receiver !== null) {
            $inputs[] = $receiver;
        }

        // Nothing says this function cannot undo an escaper's work, so an
        // escaped SQL value comes out as raw as it went in.
        return $this->transferUnion($op, $inputs, sprintf(
            $internal->receiver
                ? 'PHP declares %s to return %s, so the result carries the text of its arguments and its object.'
                : 'PHP declares %s to return %s, so the result carries the text of its arguments.',
            $name,
            $internal->returns,
        ), revertResiduals: true) || $changed;
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
            ? $this->state->addShape($target, Shape::rest(Shape::of($taint)), $provenance)
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

        // As for an include: a probe run records where the seed would have
        // gone, key by key when the argument has keys, and the caller
        // publishes what it passed.
        if ($this->seedParameterIndex !== null) {
            if ($args === null) {
                return false;
            }

            foreach ($targets as $target) {
                $this->recordScopeReference(
                    'in',
                    strtolower($target . '::{main}'),
                    'args',
                    $this->state->valueShapeOf($args),
                );
            }

            return false;
        }

        $scope = [];
        $origins = [];

        // The keys travel too, so a template reading `$args['id']` is no more
        // a finding than reading `$context['id']` in the file that built the
        // array.
        if ($args !== null) {
            $value = $this->state->valueShapeOf($args);

            if (! $value->isEmpty()) {
                $scope['args'] = $value;
                $origin = $this->scopeTrace($op, $args, 'args', $value->flatten());

                if ($origin !== []) {
                    $origins['args'] = $origin;
                }
            }
        }

        $changed = false;

        foreach ($targets as $target) {
            $key = strtolower($target . '::{main}');
            $changed = $this->scopes->addInto($key, $scope, $origins) || $changed;
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
        if ($sanitizer->clearsBy === Sanitizer::FILTER) {
            return $this->transferFilter($op, $call, $sanitizer, $matcher);
        }

        $incoming = $this->state->unionOf($call->arguments);

        // A pattern decides which parts of the subject are replaced. Its own
        // text never reaches the result, so a pattern built from a stored
        // setting, `preg_quote( $separator )`, does not taint every price the
        // replacement trims.
        if ($sanitizer->clearsBy === Sanitizer::ALLOWLIST_PATTERN) {
            $incoming = $this->state->unionOf(array_values(array_filter(
                $call->arguments,
                static fn (int $index): bool => $index !== $sanitizer->patternArgument,
                ARRAY_FILTER_USE_KEY,
            )));
        }

        if ($sanitizer->requiresLiteralArgument !== null) {
            $formatArgument = $call->argument($sanitizer->requiresLiteralArgument);

            if ($formatArgument !== null && $this->formatStringIsUnsafe($formatArgument)) {
                return $this->reportNonLiteralSanitizer($op, $call, $sanitizer, $matcher, $formatArgument);
            }
        }

        if ($sanitizer->imprecise) {
            $this->imprecise = true;
        }

        $proof = $sanitizer->clearsBy === null ? null : $this->strategyClears($sanitizer, $call);
        $cleared = $sanitizer->transform(
            $incoming,
            $sanitizer->clearsBy === null ? null : ($proof->clears ?? TaintSet::empty()),
            $proof->sqlQuotedOnly ?? false,
            $proof->csvPrefixOnly ?? false,
        );

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
     * `filter_var( $v, FILTER_VALIDATE_INT )`: the value, less what the filter
     * proves it cannot carry.
     */
    private function transferFilter(Op\Expr $op, CallTarget $call, Sanitizer $sanitizer, Matcher $matcher): bool
    {
        $value = $call->argument($sanitizer->arguments->firstIndex());
        $incoming = $value === null ? TaintSet::empty() : $this->state->effectiveTaintOf($value);

        [$taint, $proof, $filter] = $this->applyFilter(
            $call,
            $incoming,
            $sanitizer->filterArgument,
            $sanitizer->optionsArgument,
        );

        if ($taint->isEmpty()) {
            return $this->writeResult($op->result, $taint);
        }

        // A kind the filter proved gone can only have come from the options,
        // so the trace looks there first.
        $options = $sanitizer->optionsArgument === null ? null : $call->argument($sanitizer->optionsArgument);
        $inputs = array_values(array_filter($proof === null ? [$value, $options] : [$options, $value]));

        return $this->writeResult($op->result, $taint, new Provenance(
            $proof === null ? TraceVerb::Propagate : TraceVerb::Sanitize,
            $op,
            $proof === null
                ? sprintf('%s with %s passes the value through.', $matcher->describe(), $filter)
                : sprintf('%s with %s leaves %s.', $matcher->describe(), $filter, $taint->describe()),
            $inputs,
        ));
    }

    /**
     * What a filter leaves of a value, and the options as written.
     *
     * The options count raw: `options.default` is what comes back when the
     * filter fails, and it is not filtered.
     *
     * @return array{0: TaintSet, 1: CharacterProof|null, 2: string} the taint, the
     *                                                            filter's proof, and
     *                                                            the filter's name
     */
    private function applyFilter(CallTarget $call, TaintSet $incoming, ?int $filterAt, ?int $optionsAt): array
    {
        $name = FilterProof::nameOf($filterAt === null ? null : $call->argument($filterAt));
        $proof = FilterProof::of($name);

        // A filter that proves something is a sanitizer, and like any other it
        // settles where the value came from and whether it was cleaned.
        $taint = $proof === null
            ? $incoming
            : $proof->apply($incoming)->without(TaintSet::of(TaintKind::Unknown, TaintKind::Storage));

        $options = $optionsAt === null ? null : $call->argument($optionsAt);

        if ($options !== null) {
            $taint = $taint->union($this->state->effectiveTaintOf($options));
        }

        $label = match ($name) {
            null => 'no filter',
            '' => 'a filter that is not a constant',
            default => $name,
        };

        return [$taint, $proof, $label];
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

        $reverts = $summary->revertedResidualsFor($index);

        foreach ($summary->propertiesFor($index) as [$class, $property, $reached]) {
            // Only what survives the body, part by part. The kinds were
            // recorded by the probe run, whose seed carried every kind: what
            // reached the property is what the body let through.
            $value = $reached->mapSets(
                static fn (TaintSet $kinds): TaintSet => self::throughBody($argumentTaint, $kinds, $reverts),
            );

            // The escaping ledger stays out of an option, as it does for a
            // write in this body: see recordOptionWrite(). throughBody()
            // hands `escaped` back alongside `html`.
            if ($class === self::OPTION_STORE) {
                $value = $value->without(TaintSet::of(TaintKind::Escaped, TaintKind::EscapeVoided));
            }

            if ($value->isEmpty()) {
                continue;
            }

            // An option the callee writes is saved by this call, so this
            // frame decides whether only an administrator can make it. The
            // callee saw only its own body, and a handler usually checks the
            // capability and then calls a helper that saves.
            if ($class === self::OPTION_STORE && $this->onlyAdministratorsHere()) {
                continue;
            }

            $changed = $this->properties->add(
                $class,
                $property,
                $value,
                $this->propertyWriteTrace($op, $argument, $value->flatten(), $summary, $property, $class),
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
     * The captures a callee's parameter reaches, fed with what this caller
     * actually passed.
     *
     * A probe run must not publish — its seed is a question — so it re-records
     * instead, which is what carries a capture through a helper chain: A's
     * probe applying B's summary learns that A's parameter reaches B's
     * closure, and A's own summary says so to A's callers.
     */
    private function applySummaryCaptures(
        Op\Expr $op,
        FunctionSummary $summary,
        int $index,
        Operand $argument,
        TaintSet $argumentTaint,
    ): bool {
        if ($argumentTaint->isEmpty() || $summary->capturesFor($index) === []) {
            return false;
        }

        $changed = false;

        foreach ($summary->capturesFor($index) as [$closureKey, $name, $kinds]) {
            // Only what survives the body, as for properties.
            $taint = self::throughBody($argumentTaint, $kinds, $summary->revertedResidualsFor($index));

            if ($taint->isEmpty()) {
                continue;
            }

            if ($this->seedParameterIndex !== null) {
                $this->recordCaptureReference($closureKey, $name, $taint);

                continue;
            }

            $changed = $this->scopes->addInto(
                $closureKey,
                [$name => Shape::of($taint)],
                [$name => $this->captureWriteTrace($op, $argument, $taint, $summary, $name)],
            ) || $changed;
        }

        return $changed;
    }

    /**
     * The shared scopes a callee's parameter reaches, fed with what this
     * caller actually passed: the file the callee includes, the template it
     * loads, the variable its closure writes back.
     *
     * A probe run re-records instead of publishing, which carries the scope
     * through a helper chain exactly as it carries a capture: A's probe
     * applying B's summary learns that A's parameter reaches the template B
     * includes, and A's summary tells A's callers.
     */
    private function applySummaryScopes(
        Op\Expr $op,
        FunctionSummary $summary,
        int $index,
        Operand $argument,
        TaintSet $argumentTaint,
    ): bool {
        $references = $summary->scopesFor($index);

        if ($argumentTaint->isEmpty() || $references === []) {
            return false;
        }

        $changed = false;

        $reverts = $summary->revertedResidualsFor($index);

        foreach ($references as [$table, $key, $name, $reached]) {
            // Only what survives the body, part by part, as for properties. A
            // form id that the callee passes through absint() on its way to an
            // included file's `$settings` hands that file an object id, not
            // the whole request it came from.
            $value = $reached->mapSets(
                static fn (TaintSet $kinds): TaintSet => self::throughBody($argumentTaint, $kinds, $reverts),
            );

            if ($value->isEmpty()) {
                continue;
            }

            if ($this->seedParameterIndex !== null) {
                $this->recordScopeReference($table, $key, $name, $value);

                continue;
            }

            $taint = $value->flatten();
            $origins = [$name => $this->scopeWriteTrace($op, $argument, $taint, $summary, $table, $name)];

            $changed = ($table === 'out'
                ? $this->scopes->addOutOf($key, [$name => $value], $origins)
                : $this->scopes->addInto($key, [$name => $value], $origins)) || $changed;
        }

        return $changed;
    }

    /**
     * What of a caller's argument reaches a place its callee writes it to.
     *
     * `$reached` is what the probe run saw arrive there, with the parameter
     * seeded with every kind. The seed leaves out the four derived kinds,
     * which only an escaper or the engine may claim, so the record says
     * nothing about them directly. Each rides with the kind it qualifies:
     * `escaped` and `escape_voided` with HTML, `sql_unquoted` with SQL, and
     * `unknown` only when the body cleared nothing, since any sanitiser
     * settles it. An argument escaped and then filtered keeps that history
     * through a setter that stores it as it came.
     *
     * The callee's own escaping and voiding are in the record already, as
     * markers it made itself.
     */
    private static function throughBody(TaintSet $argument, TaintSet $reached, ?TaintSet $reverts = null): TaintSet
    {
        $carried = TaintSet::empty();

        if ($reached->has(TaintKind::Html)) {
            $carried = $carried->with(TaintKind::Escaped, TaintKind::EscapeVoided);
        }

        if (TaintSet::allDataflowKinds()->isSubsetOf($reached)) {
            $carried = $carried->with(TaintKind::Unknown);
        }

        return $argument->intersect($reached->union($carried))
            ->union(self::madeFrom($argument, $reached))
            ->union(self::residualsThrough($argument, $reached, $reverts));
    }

    /**
     * The escaped SQL residuals an argument brings back through a body that
     * lets its `sql` through.
     *
     * The probe seeds `sql` alone, so the record says nothing about a residual
     * directly. One rides with `sql`: `function id( $v ) { return $v; }`
     * hands `esc_sql( $v )` back escaped. A body that may have undone the
     * escaping hands it back as `sql`.
     */
    private static function residualsThrough(TaintSet $argument, TaintSet $reached, ?TaintSet $reverts): TaintSet
    {
        $through = TaintSet::empty();
        $residuals = $argument->intersect(self::sqlResiduals());

        if (! $residuals->isEmpty() && $reached->has(TaintKind::Sql)) {
            $through = $reverts !== null && ! $reverts->intersect(self::sqlResiduals())->isEmpty()
                ? TaintSet::of(TaintKind::Sql)
                : $residuals;
        }

        // A formula behind an apostrophe rides with `csv` the same way.
        if ($argument->has(TaintKind::CsvPrefixed) && $reached->has(TaintKind::Csv)) {
            $through = $through->with(
                $reverts !== null && $reverts->has(TaintKind::CsvPrefixed) ? TaintKind::Csv : TaintKind::CsvPrefixed,
            );
        }

        return $through;
    }

    /**
     * The escaped SQL residuals a callee made from the argument's `sql`.
     *
     * The probe run seeds the parameter with payload kinds only, so what it saw
     * arrive is what the body made of them. `function q( $v ) { return esc_sql(
     * $v ); }` returns `sql_unquoted`, which the argument does not carry until
     * the callee escapes it. Keeping only the kinds both share lost it, and an
     * escaped wrapper's return used unquoted was clean.
     */
    private static function madeFrom(TaintSet $argument, TaintSet $reached): TaintSet
    {
        $made = $argument->has(TaintKind::Sql) ? $reached->intersect(self::sqlResiduals()) : TaintSet::empty();

        // `function acme_cell( $v ) { return preg_replace( '/^([=+\-@])/', "'$1", $v ); }`
        return $argument->has(TaintKind::Csv) && $reached->has(TaintKind::CsvPrefixed)
            ? $made->with(TaintKind::CsvPrefixed)
            : $made;
    }

    /**
     * The trace of a scope write that happened inside a callee.
     *
     * @return list<TraceStep>
     */
    private function scopeWriteTrace(
        Op\Expr $op,
        Operand $argument,
        TaintSet $taint,
        FunctionSummary $summary,
        string $table,
        string $name,
    ): array {
        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null) {
            return [];
        }

        $callee = $summary->displayName;
        $description = match (true) {
            $table === 'out' => sprintf('Passed to %s(), which writes it back to $%s.', $callee, $name),
            $name === 'args' => sprintf('Passed to %s(), which hands it to a template as $args.', $callee),
            default => sprintf('Passed to %s(), where an included file sees it as $%s.', $callee, $name),
        };

        return $this->traces->build(
            $argument,
            $kind,
            $this->traces->step(TraceVerb::Propagate, $op, $taint, $description),
        );
    }

    /**
     * The trace of a capture that happened inside a callee.
     *
     * @return list<TraceStep>
     */
    private function captureWriteTrace(
        Op\Expr $op,
        Operand $argument,
        TaintSet $taint,
        FunctionSummary $summary,
        string $name,
    ): array {
        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null) {
            return [];
        }

        return $this->traces->build($argument, $kind, $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            sprintf('Passed to %s(), where a closure captures it as $%s.', $summary->displayName, $name),
        ));
    }

    /**
     * The options table as one more property owner.
     *
     * `update_option( 'acme_x', $request )` then `get_option( 'acme_x' )` in
     * another function is a second-order flow with both ends visible, and the
     * stored-source baseline flattened it into "an option might hold anything".
     * Tracking the write per key — in the same map property writes use, under
     * an owner no class name can collide with — lets the read carry what
     * actually went in, with the write in the trace. The `#` is the collision
     * guard: not a character a PHP class name can start with.
     */
    private const OPTION_STORE = '#options';

    /**
     * Option writers: function => [key argument, value argument].
     *
     * Public for {@see \Enshrined\WpTaint\Scan\Scanner}, which works out who
     * can reach a call to one of these before the analysis starts.
     */
    public const OPTION_WRITERS = [
        'update_option' => [0, 1],
        'add_option' => [0, 1],
        'update_site_option' => [0, 1],
    ];

    /** Option readers: function => key argument. */
    private const OPTION_READERS = [
        'get_option' => 0,
        'get_site_option' => 0,
    ];

    /**
     * Record what an option write put under its key, when the key folds.
     *
     * The whole value goes in, its elements and keys with it. A plugin saves
     * its settings as one array far more often than as a single value, and
     * reading only the array's own taint stored nothing for it:
     *
     *     update_option( 'acme', array( 'target' => $_POST['url'] ) );
     *
     *     $settings = get_option( 'acme' );
     *     wp_redirect( $settings['target'] );   // was missed
     *
     * A write only an administrator can make stores nothing. Administrators
     * are trusted in WordPress, so a read of what they saved carries what
     * get_option() carries anyway: stored data, with no `url` or `path` in
     * it. WP File Manager's preferences screen saves a path the request
     * chose, on a page only `manage_options` reaches, and that path reaching
     * `include` is the administrator's own choice. Anyone else's write keeps
     * everything it carried. See {@see AdministratorReach}.
     *
     * The probe run records the reach instead of performing the write — the
     * same split every property write uses — so a helper wrapping
     * update_option() carries its caller's taint into the store through
     * paramToProperty, with no machinery of its own. The caller judges its
     * own call site the same way: see {@see applySummaryProperties()}.
     */
    private function recordOptionWrite(Op\Expr $op, CallTarget $call, Matcher $matcher): bool
    {
        $spec = $matcher->kind === MatcherKind::Func ? (self::OPTION_WRITERS[$matcher->name] ?? null) : null;

        if ($spec === null) {
            return false;
        }

        $key = $call->argument($spec[0]);
        $value = $call->argument($spec[1]);

        if ($key === null || $value === null) {
            return false;
        }

        $names = $this->resolver->values()->knownStrings($key);

        if ($names === [] || count($names) > 4) {
            return false;
        }

        // Content kinds cross the store; the escaping ledger does not. Whether
        // the value was escaped before storage says nothing about the context
        // it will eventually land in — WordPress's own convention is escape at
        // output whatever was done at input — and carrying `escaped` through
        // made every read through the filterable get_option() re-report the
        // write's escaping as voided, on a line the output rule already owns.
        $taint = $this->state->effectiveTaintOf($value)
            ->without(TaintSet::of(TaintKind::Escaped, TaintKind::EscapeVoided));

        if (! $taint->isEmpty() && $this->onlyAdministratorsHere()) {
            $taint = TaintSet::empty();
        }

        $changed = false;

        // An option is one set: a read hands back the whole value.
        foreach ($names as $name) {
            $this->recordPropertyReference(self::OPTION_STORE, $name, Shape::of($taint));

            $changed = $this->properties->add(
                self::OPTION_STORE,
                $name,
                Shape::of($taint),
                $this->optionWriteTrace($op, $value, $taint, $name),
            ) || $changed;
        }

        return $changed;
    }

    /**
     * Whether only an administrator can be at the op being transferred.
     *
     * Either a check of a site-wide grant dominates its block, or every way
     * the scan can see into this function passes one. A nonce proves neither,
     * because a subscriber holds a valid nonce for every form they can see.
     * Nor does a role such as `edit_posts`, which every author has.
     */
    private function onlyAdministratorsHere(): bool
    {
        if ($this->administrators?->onlyAdministratorsReach($this->context->key) ?? false) {
            return true;
        }

        if ($this->siteWideGuards === null) {
            $this->siteWideGuards = CapabilityGuard::siteWide($this->registry, $this->callGraph);
            $this->siteWideGuards->forFunction($this->blocks);
        }

        return $this->siteWideGuards->isEntitled($this->currentBlock);
    }

    /**
     * What the store holds under the keys a read can name, and the trace of
     * the write that put it there.
     *
     * A key that will not fold reads nothing extra: the stored baseline
     * already covers "an option whose name we cannot pin down".
     *
     * @return array{0: TaintSet, 1: list<TraceStep>}
     */
    private function optionStoreTaint(Matcher $matcher, CallTarget $call): array
    {
        $index = $matcher->kind === MatcherKind::Func ? (self::OPTION_READERS[$matcher->name] ?? null) : null;
        $key = $index === null ? null : $call->argument($index);

        if ($key === null) {
            return [TaintSet::empty(), []];
        }

        $taint = TaintSet::empty();
        $origin = [];

        foreach ($this->resolver->values()->knownStrings($key) as $name) {
            $stored = $this->properties->get(self::OPTION_STORE, $name);

            if ($origin === [] && ! $stored->isEmpty()) {
                $origin = $this->properties->originOf(self::OPTION_STORE, $name);
            }

            $taint = $taint->union($stored);
        }

        return [$taint, $origin];
    }

    /**
     * @return list<TraceStep>
     */
    private function optionWriteTrace(Op\Expr $op, Operand $value, TaintSet $taint, string $name): array
    {
        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null || $this->seedParameterIndex !== null) {
            return [];
        }

        return $this->traces->build($value, $kind, $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            sprintf("Written to the option '%s'.", $name),
        ));
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
        ?string $class = null,
    ): array {
        $kind = $taint->kinds()[0] ?? null;

        if ($kind === null || $this->seedParameterIndex !== null) {
            return [];
        }

        return $this->traces->build($argument, $kind, $this->traces->step(
            TraceVerb::Propagate,
            $op,
            $taint,
            $class === self::OPTION_STORE
                ? sprintf("Passed to %s(), which stores it in the option '%s'.", $summary->displayName, $property)
                : sprintf('Passed to %s(), which writes it into $%s.', $summary->displayName, $property),
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
    private function strategyClears(Sanitizer $sanitizer, CallTarget $call): ?CharacterProof
    {
        if ($sanitizer->clearsBy !== Sanitizer::ALLOWLIST_PATTERN) {
            return null;
        }

        $pattern = $call->argument($sanitizer->patternArgument);
        $replacement = $call->argument($sanitizer->replacementArgument);

        $patternLiteral = $pattern === null ? null : OperandHelper::literalString($pattern);
        $replacementLiteral = $replacement === null ? null : OperandHelper::literalString($replacement);

        if ($patternLiteral === null || $replacementLiteral === null) {
            return null;
        }

        return AllowlistPattern::clears($patternLiteral, $replacementLiteral);
    }

    private function formatStringIsUnsafe(Operand $formatArgument): bool
    {
        if ($this->literals->isEffectivelyLiteral($formatArgument, $this->context, $this->types)) {
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

        // A non-literal format string is the injection surface, and the result
        // carries its taint. The *placeholder arguments* are a different matter:
        // prepare() still substitutes and escapes every `%s`/`%d`/`%i` argument
        // whether or not the template was literal, so a value bound to a
        // placeholder does not reach the query as raw SQL. Passing the union of
        // all arguments through — as an earlier version did — laundered the
        // template's failure onto its bound arguments and reported the outer
        // `$wpdb->query()` as an unprepared-query sink on a value that prepare()
        // had in fact escaped (`$wpdb->query( $wpdb->prepare( "… {$table} …
        // source_url = %s", $source_url ) )`). The template's own taint is what
        // survives; the arguments' taint does not.
        return $this->writeResult(
            $op->result,
            $this->state->taintOf($formatArgument),
            new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf(
                    '%s was called with a non-literal format string, so it escapes nothing. Its placeholder '
                        . 'arguments are still bound and escaped; the format string itself is not.',
                    $matcher->describe(),
                ),
                $call->arguments,
            ),
        );
    }

    private function transferPropagator(Op\Expr $op, CallTarget $call, Propagator $propagator, Matcher $matcher): bool
    {
        $inputs = [];

        foreach ($propagator->arguments->resolve($call->argumentCount()) as $index) {
            $argument = $call->argument($index);

            if ($argument !== null) {
                $inputs[] = $argument;
            }
        }

        $description = $propagator->note
            ?? sprintf('%s passes its argument through unchanged.', $matcher->describe());

        // array_keys() returns keys, so it reads what the array's keys carry
        // and not what element writes put into its values. See keysOf().
        if ($matcher->key() === 'function:array_keys' && $inputs !== []) {
            return $this->writeResult(
                $op->result,
                $this->keysOf($inputs[0]),
                new Provenance(TraceVerb::Propagate, $op, $description, $inputs),
            );
        }

        if ($propagator->formatArgument !== null) {
            $formatted = $this->transferFormat($op, $call, $propagator, $matcher);

            if ($formatted !== null) {
                return $formatted;
            }
        }

        // A plain call hands the function the value itself and gets back what
        // it returns. A dispatcher can hand it an array's items instead,
        // `array_map()`, or collect its returns into an array, and there each
        // argument and the result sit a level away from what the function
        // reads and returns. See {@see CallTarget::$positional}.
        $plain = $call->positional && $this->resultMode === CallResultMode::Value;

        if ($plain && $matcher->key() === 'function:array_column') {
            $column = $this->transferColumn($op, $call, $description);

            if ($column !== null) {
                return $column;
            }
        }

        if ($plain && $propagator->returnsElement && $inputs !== [] && $this->keepsResiduals($call, $propagator)) {
            $element = $this->transferElementOf($op, $inputs, $description);

            if ($element !== null) {
                return $element;
            }
        }

        $escape = $propagator->readsEscapes ? $this->escapeReading($call) : null;

        return $this->transferUnion(
            $op,
            $inputs,
            $escape === null ? $description : sprintf(
                '%s %s, so the value is safe only %s.',
                $matcher->describe(),
                $escape === TaintKind::SqlUnticked
                    ? 'doubles or removes every backtick'
                    : 'escapes the backslash and then both quotes',
                $escape === TaintKind::SqlUnticked ? 'inside backticks' : 'inside quotes',
            ),
            keepsKeys: $propagator->keepsKeys,
            revertResiduals: ! $this->keepsResiduals($call, $propagator),
            sqlBecomes: $escape,
            keepsValues: $propagator->keepsValues,
            direct: $plain,
        );
    }

    /**
     * `reset( $rows )`, `end()`, `array_shift()`: one element of the input,
     * with what it holds below itself, so `reset( $rows )['title']` reads
     * only the rows' titles. Null when a guard vouched for an input, which
     * reads it as one set.
     *
     * @param non-empty-list<Operand> $inputs
     */
    private function transferElementOf(Op\Expr $op, array $inputs, string $description): ?bool
    {
        $taint = TaintSet::empty();
        $structure = Shape::empty();

        foreach ($inputs as $input) {
            if ($this->proofFor($input, $this->currentBlock) !== null) {
                return null;
            }

            $element = $this->state->shapeOf($input)->anyElement();
            $taint = $taint->union($this->state->taintOf($input))->union($element->own());
            $structure = $structure->join($element->structure());
        }

        $provenance = new Provenance(TraceVerb::Propagate, $op, $description, $inputs);
        $changed = $this->writeResult($op->result, $taint, $taint->isEmpty() ? null : $provenance);

        return $this->state->addShape($op->result, $structure, $provenance) || $changed;
    }

    /**
     * `array_column( $rows, 'title', 'id' )`: each row's element under the
     * column key, under a computed key, with each row's index column as the
     * keys. A column key the resolver cannot name reads any element of each
     * row, and a null column hands back the rows whole. The column and index
     * arguments only pick elements, as a key does in a read.
     *
     * Null when a guard vouched for the rows, which reads them as one set.
     */
    private function transferColumn(Op\Expr $op, CallTarget $call, string $description): ?bool
    {
        $input = $call->argument(0);

        if ($input === null || $this->proofFor($input, $this->currentBlock) !== null) {
            return null;
        }

        $rows = $this->state->shapeOf($input)->anyElement();
        $column = $this->columnOf($rows, $call->argument(1));
        $provenance = new Provenance(TraceVerb::Propagate, $op, $description, [$input]);

        // What the array and each row carry as a whole, every column carries.
        $whole = $this->state->taintOf($input)->union($rows->own());
        $changed = $this->writeResult($op->result, TaintSet::empty());
        $changed = $this->state->addShape(
            $op->result,
            Shape::rest(Shape::node($whole->union($column->own()), $column->structure())),
            $provenance,
        ) || $changed;

        $index = $call->argument(2);

        if ($index === null || self::isNull($index)) {
            return $changed;
        }

        $keys = $whole->union($this->columnOf($rows, $index)->flatten());

        return $this->state->addShape($op->result, Shape::keys($keys), $provenance) || $changed;
    }

    /**
     * What each row holds under `$column`: the element under a key the
     * resolver names, and the whole row for a null column. A key it cannot
     * name could be null too, so it reads the row and any element of it.
     */
    private function columnOf(Shape $rows, ?Operand $column): Shape
    {
        if ($column === null || self::isNull($column)) {
            return $rows;
        }

        $keys = $this->namedKeys($column);

        if ($keys === null) {
            return $rows->join($rows->anyElement());
        }

        $element = $rows->restPart();

        foreach ($keys as $key) {
            $element = $element->join($rows->elementAt($key));
        }

        return $element;
    }

    /**
     * An argument written as `null`, which php-cfg reads as a constant.
     */
    private static function isNull(Operand $operand): bool
    {
        if ($operand instanceof Operand\NullOperand) {
            return true;
        }

        if ($operand instanceof Operand\Literal) {
            return $operand->value === null;
        }

        $definition = OperandHelper::definingOp($operand);

        return $definition instanceof Op\Expr\ConstFetch
            && strtolower(ltrim(OperandHelper::literalString($definition->name) ?? '', '\\')) === 'null';
    }

    /**
     * What a `str_replace()` with literal arguments escapes SQL for, or null.
     *
     * Two readings, and only two, because the order is what makes each one
     * work. Every backtick doubled, `str_replace( '`', '``', $v )`, or removed:
     * the value cannot leave a backtick-quoted identifier. The backslash
     * escaped first and then both quotes: the value cannot leave a quoted
     * literal. Escaping the quotes first and the backslash after would turn the
     * `\'` just written into `\\'`, which ends the literal.
     */
    private function escapeReading(CallTarget $call): ?TaintKind
    {
        $search = $this->literalStrings($call->argument(0));
        $replace = $this->literalStrings($call->argument(1));

        if ($search === null || $replace === null) {
            return null;
        }

        if ($search === ['`'] && ($replace === ['``'] || $replace === [''])) {
            return TaintKind::SqlUnticked;
        }

        $escapes = ['\\' => '\\\\', "'" => "\\'", '"' => '\\"'];

        if (count($search) !== 3 || count($replace) !== 3 || $search[0] !== '\\') {
            return null;
        }

        foreach ($search as $position => $character) {
            if (($escapes[$character] ?? null) !== $replace[$position]) {
                return null;
            }
        }

        return count(array_unique($search)) === 3 ? TaintKind::SqlUnquoted : null;
    }

    /**
     * The strings an argument holds when it is one known string or an array
     * literal of them, in order. Null for anything else.
     *
     * Known the way a concatenation's fragments are: a literal, or a value that
     * folds to exactly one string. Yoast's ORM keeps the backtick in a
     * variable, `str_replace( $q, $q . $q, $part )`.
     *
     * @return list<string>|null
     */
    private function literalStrings(?Operand $operand): ?array
    {
        if ($operand === null) {
            return null;
        }

        $single = $this->knownText($operand);

        if ($single !== null) {
            return [$single];
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->literalStrings($definition->expr);
        }

        if (! $definition instanceof Op\Expr\Array_) {
            return null;
        }

        $strings = [];

        foreach ($definition->values as $value) {
            $string = $value instanceof Operand ? $this->knownText($value) : null;

            if ($string === null) {
                return null;
            }

            $strings[] = $string;
        }

        return $strings;
    }

    /**
     * Whether a propagator leaves an escaped SQL value's residual in place.
     *
     * Only one the catalogue says cannot undo the escaping, called without the
     * argument that could, and for `implode()` a glue that leaves the quotes as
     * it found them: `','` or `"', '"`, not `"'"`.
     */
    private function keepsResiduals(CallTarget $call, Propagator $propagator): bool
    {
        if ($propagator->glueArgument !== null) {
            $glue = $call->argumentCount() === 1 ? '' : $this->knownText($call->argument($propagator->glueArgument));

            return $glue !== null && self::keepsQuotes($glue);
        }

        if (! $propagator->keepsResiduals) {
            return false;
        }

        return $propagator->maskArgument === null || $call->argument($propagator->maskArgument) === null;
    }

    /**
     * Whether a run of text leaves every quote state as it found it.
     */
    private static function keepsQuotes(string $text): bool
    {
        foreach ([SqlQuote::None, SqlQuote::Single, SqlQuote::Double, SqlQuote::Backtick] as $state) {
            if ($state->after($text)[0] !== $state) {
                return false;
            }
        }

        return true;
    }

    /**
     * The one string an operand is known to hold, or null.
     */
    private function knownText(?Operand $operand): ?string
    {
        if ($operand === null) {
            return null;
        }

        $literal = OperandHelper::literalString($operand);

        if ($literal !== null) {
            return $literal;
        }

        $folded = $this->resolver->values()->strings($operand);

        return count($folded) === 1 ? $folded[0] : null;
    }

    /**
     * `sprintf( "WHERE name = '%s'", esc_sql( $n ) )`: a literal format read
     * as the text it writes, with each argument folded where the format puts
     * it. A numeric conversion writes a number and carries nothing of its
     * argument. Null for a format that is not a literal this can read.
     */
    private function transferFormat(Op\Expr $op, CallTarget $call, Propagator $propagator, Matcher $matcher): ?bool
    {
        $at = (int) $propagator->formatArgument;
        $format = $this->knownText($call->argument($at));
        $pieces = $format === null ? null : PrintfFormat::pieces($format);

        if ($pieces === null) {
            return null;
        }

        $parts = [];
        $inputs = [];

        foreach ($pieces as $piece) {
            if (is_string($piece)) {
                $parts[] = [$piece, TaintSet::empty()];

                continue;
            }

            $argument = $propagator->formatArray
                ? $call->argument($at + 1)
                : $call->argument($at + 1 + $piece);

            if ($argument === null) {
                continue;
            }

            // The whole value is written as text, elements and all:
            // `implode()` hands back its elements' taint as a container.
            $inputs[] = $argument;
            $parts[] = [null, $this->guardedEffectiveTaintOf($argument)];
        }

        $taint = SqlQuoteFold::fold($parts);

        return $this->writeResult(
            $op->result,
            $taint,
            $taint->isEmpty() ? null : new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf('%s writes its arguments where its format puts them.', $matcher->describe()),
                $inputs,
            ),
        );
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

        // A method's receiver is an input too: an unknown method can return
        // what its object holds, and without this a value stored into an
        // object by one unknown call could never come back out of another.
        //
        // Not for a method the scan declares, on a receiver whose class it
        // could not find: that is one of those declarations, and the engine
        // cannot say which, but it can say none of them is unknown. The call is
        // usually a lookup, and `$form = wpcf7_contact_form( $_POST['id'] );
        // $form->title()` would make a form's stored title as attacker-chosen
        // as the id used to find it. Only when nothing about the callee can be
        // seen, its name unknown or declared nowhere in the scan.
        $receiver = $op instanceof Op\Expr\MethodCall && $this->calleeUnseen($call) ? $op->var : null;
        $inputs = $receiver === null ? $call->arguments : [...$call->arguments, $receiver];

        if ($this->options->dynamicCalls === DynamicCallPolicy::Clean) {
            return $this->writeResult($op->result, TaintSet::empty());
        }

        if ($this->options->dynamicCalls === DynamicCallPolicy::Tainted) {
            $changed = $this->writeResult(
                $op->result,
                TaintSet::allDataflowKinds(),
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf(
                        'Call to %s could not be resolved, so %s.',
                        $call->name(),
                        DynamicCallPolicy::Tainted->describe(),
                    ),
                    $call->arguments,
                    imprecise: true,
                ),
            );

            return $this->applyUnknownCalleeEffects($op, $call, $receiver, TaintSet::allDataflowKinds()) || $changed;
        }

        $changed = $this->transferUnion(
            $op,
            $inputs,
            sprintf(
                'Call to %s could not be resolved, so %s.',
                $call->name(),
                DynamicCallPolicy::Propagate->describe(),
            ),
            imprecise: true,
            revertResiduals: true,
        );

        $passed = TaintSet::empty();

        foreach ($call->arguments as $argument) {
            $passed = $passed->union($this->state->effectiveTaintOf($argument));
        }

        return $this->applyUnknownCalleeEffects($op, $call, $receiver, $passed) || $changed;
    }

    /**
     * Which argument positions an unresolved call could write back through, or
     * null for any of them.
     *
     * None, when a dispatcher runs the callee: `call_user_func()` and its
     * relatives pass arguments by value. Any, when nothing about the callee can
     * be seen: its name is unknown, or
     * it is a method no class in the scan declares. A named method the scan
     * does declare, on a receiver whose class could not be found, is one of
     * those declarations, and PHP writes back only through a parameter
     * declared by reference, so only a position some declaration takes by
     * reference counts. Treating every argument of `$generator->add( $name,
     * $title, $callback, $options )` as written back spread each argument's
     * taint into the other three, and `$this->{ 'validate_' . $type }( $value,
     * $setting )` wrote the value into `$setting` through a method that takes
     * it by value.
     *
     * @return array<int, true>|null
     */
    private function byReferencePositions(CallTarget $call): ?array
    {
        // `call_user_func( $cb, $contact_form, $options )` hands `$cb` copies.
        if ($call->passesByValue) {
            return [];
        }

        if ($this->calleeUnseen($call)) {
            return null;
        }

        $positions = [];

        foreach ($call->candidates as $key) {
            $method = $this->functions->get($key);

            if ($method === null) {
                continue;
            }

            foreach ($method->parameters as $index => $parameter) {
                if (! $parameter['byRef']) {
                    continue;
                }

                if (! $parameter['variadic']) {
                    $positions[$index] = true;

                    continue;
                }

                // A variadic by-reference parameter takes every argument from
                // its position on.
                for ($position = $index; $position < count($call->arguments); $position++) {
                    $positions[$position] = true;
                }
            }
        }

        return $positions;
    }

    /**
     * Whether nothing about an unresolved callee can be seen: the scan has no
     * candidate for it. A named method has the methods of that name, and a
     * computed name on a receiver of known class has that class's methods; a
     * callable whose name is unknown, or a method no class in the scan
     * declares, has none.
     */
    private function calleeUnseen(CallTarget $call): bool
    {
        return $call->candidates === [];
    }

    /**
     * What an unknown callee may do besides return: write into its object, and
     * write back through any argument it takes by reference.
     *
     * Which parameters are by reference is part of the signature the engine
     * could not find, so every argument that names a variable is treated as
     * one, except where the scan's own declarations of a named method say
     * otherwise; see {@see byReferencePositions()}. That over-approximates, the
     * right side for a callee nothing is known about: `$cb( $_GET['a'], $out );
     * echo $out;` reported nothing.
     * Added as element taint, the same slot a known out-parameter is written
     * to, and never cleared, because SSA gives the write no operand of its own.
     */
    private function applyUnknownCalleeEffects(Op\Expr $op, CallTarget $call, ?Operand $receiver, TaintSet $taint): bool
    {
        if ($taint->isEmpty()) {
            return false;
        }

        $targets = [];
        $byReference = $this->byReferencePositions($call);

        foreach ($call->arguments as $index => $argument) {
            $writable = $byReference === null || isset($byReference[$index]);

            if ($writable && OperandHelper::variableName($argument) !== null) {
                $targets[] = $argument;
            }
        }

        if ($receiver !== null) {
            $targets[] = $receiver;
        }

        $changed = false;

        foreach ($targets as $target) {
            $provenance = new Provenance(
                TraceVerb::Propagate,
                $op,
                sprintf(
                    'Call to %s could not be resolved, so it may have written %s into %s.',
                    $call->name(),
                    $taint->describe(),
                    OperandHelper::describe($target),
                ),
                $call->arguments,
                imprecise: true,
            );

            $changed = $this->state->addShape($target, Shape::rest(Shape::of($taint)), $provenance) || $changed;
        }

        return $changed;
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
        $structure = $summary->introducesShape();
        $contributors = [];
        $contributorKeys = [];
        $viaParameters = [];
        $anyArgumentTainted = false;
        $changed = false;

        foreach ($call->arguments as $index => $argument) {
            $proof = $this->proofFor($argument, $this->currentBlock);

            // A callee summarised part by part gets each part of the argument
            // through the record of that part: see argumentPieces().
            foreach ($this->argumentPieces($call, $summary, $index, $argument) as [$record, $piece]) {
                // A guarded argument hands the callee what the guard admits.
                $argumentTaint = self::guarded($piece, $proof);

                if ($argumentTaint->isEmpty()) {
                    continue;
                }

                $anyArgumentTainted = true;
                $reverts = $record->revertedResidualsFor($index);

                // A callee that may undo escaping, called on SQL-carrying data
                // here, may undo it for this run's caller too.
                $this->noteReverted($reverts, $argumentTaint);

                // As for a side channel: the markers ride with the kind they
                // qualify, so an escaped value handed back as it came is still
                // escaped, and one of unknown origin is still unknown.
                $reached = $record->returnTaintFor($index);
                $returned = self::throughBody($argumentTaint, $reached, $reverts);

                // What the argument put into the returned array's elements and
                // keys, as for a property: the kinds that got through the body.
                $into = $record->returnShapeFor($index)->mapSets(
                    static fn (TaintSet $kinds): TaintSet => self::throughBody($argumentTaint, $kinds, $reverts),
                );
                $structure = $structure->join($into);

                if (! $returned->isEmpty() || ! $into->isEmpty()) {
                    $result = $result->union($returned);
                    $keys = $call->positional ? $summary->keysReadFrom($index) : null;

                    if ($keys !== null) {
                        $contributorKeys[count($contributors)] = $keys;
                    }

                    if (! in_array($index, $viaParameters, true)) {
                        $contributors[] = $argument;
                        $viaParameters[] = $index;
                    }
                }

                $this->reportSummarySinks($op, $call, $record, $index, $argument, $argumentTaint);
                $changed = $this->applySummaryProperties($op, $record, $index, $argument, $argumentTaint)
                    || $changed;
                $changed = $this->applySummaryCaptures($op, $record, $index, $argument, $argumentTaint)
                    || $changed;
                $changed = $this->applySummaryScopes($op, $record, $index, $argument, $argumentTaint)
                    || $changed;
            }

            // A callee that rebuilds this parameter key by key hands each
            // element of the argument back under its own key.
            $each = $this->eachElementBack($summary, $index, $argument, $proof);
            $structure = $structure->join($each);

            if (! $each->isEmpty() && ! in_array($index, $viaParameters, true)) {
                $anyArgumentTainted = true;
                $contributors[] = $argument;
                $viaParameters[] = $index;
            }
        }

        $result = self::withoutUnearnedEscapeMarkers($result, $anyArgumentTainted);
        $structure = $structure->mapSets(
            static fn (TaintSet $kinds): TaintSet => self::withoutUnearnedEscapeMarkers($kinds, $anyArgumentTainted),
        );

        $changed = $this->applySummaryByRefEffects($op, $call, $summary->withoutParts()) || $changed;

        $everything = $result->union($structure->flatten());

        if ($everything->isEmpty()) {
            return $this->writeResult($op->result, $result) || $changed;
        }

        $provenance = new Provenance(
            TraceVerb::Return_,
            $op,
            $this->describeReturn($summary, $viaParameters, $everything),
            $contributors,
            callee: $summary->displayName,
            parameterIndex: $viaParameters[0] ?? null,
            predecessorKeys: $contributorKeys,
        );

        $changed = $this->writeResult($op->result, $result, $provenance) || $changed;

        return $this->writeReturnedElements($op->result, $structure, $provenance) || $changed;
    }

    /**
     * The taint an argument hands the callee's parameter.
     *
     * Every slot of it: the callee receives the whole value, and an array
     * passed in arrives with its elements attached. Reading only the own slot
     * loses every flow through `f( array( $_GET['v'] ) )`. A callee that reads
     * the parameter only through literal keys sees only those elements, and
     * what the array carries as a whole or under a computed key. See
     * {@see ParameterKeyReads}.
     */
    /**
     * What a callee that rebuilds a parameter key by key hands back: each
     * literal key's element of the argument under that key, and what the
     * argument carries as a whole or under a computed key under a computed
     * key. See {@see FunctionSummary::returnEachFor()}.
     *
     *     $clean = acme_clean( array( 'name' => $_GET['n'], 'mode' => 'grid' ) );
     *     echo $clean['mode'];   // clean: only `name` held request data
     */
    private function eachElementBack(
        FunctionSummary $summary,
        int $index,
        Operand $argument,
        ?CharacterProof $proof,
    ): Shape {
        if ($summary->paramToReturnEach === [] || $this->resultMode === CallResultMode::Discard) {
            return Shape::empty();
        }

        $shape = $this->state->shapeOf($argument);
        $back = Shape::empty();

        foreach ($shape->elements() as $key => $element) {
            $taint = self::eachBack($summary, $index, $element->flatten(), [ParameterParts::step($key)], $proof);
            $back = $back->join(Shape::element($key, Shape::of($taint)));
        }

        $own = $this->state->taintOf($argument)->union($shape->own());
        $rest = self::eachBack($summary, $index, $own, [], $proof)
            ->union(self::eachBack($summary, $index, $shape->restPart()->flatten(), [ParameterParts::ANY], $proof));

        return $back->join(Shape::rest(Shape::of($rest)));
    }

    /**
     * What `$taint`, at `$path` in the argument, brings back under its own key
     * through the part of the parameter that covers `$path`.
     *
     * @param list<int|string> $path
     */
    private static function eachBack(
        FunctionSummary $summary,
        int $index,
        TaintSet $taint,
        array $path,
        ?CharacterProof $proof,
    ): TaintSet {
        $part = self::coveringPart($path, $summary->partsFor($index));
        $each = $summary->forPart($index, $part)->returnEachFor($index);

        if ($each->isEmpty() || $taint->isEmpty()) {
            return TaintSet::empty();
        }

        return self::throughBody(self::guarded($taint, $proof), $each, $summary->revertedResidualsFor($index));
    }

    /**
     * What a call hands one parameter, split by the parts the callee reads it
     * through, each piece with the summary as its part sees it.
     *
     * A callee summarised part by part knows which of its parameter's parts
     * reached what: see {@see ParameterParts}. Each node of the argument's
     * shape goes to the most specific part whose path covers the node, and
     * what no part covers goes to part 0, the parameter's own taint, which
     * every part inherits. A part's seed reaches whatever a read of anything
     * below it reaches, so each piece reaches no more than its part does, and
     * no less than the argument's taint there would.
     *
     *     output_fields( array( array( 'value' => $stored, 'desc' => 'Text' ) ) );
     *
     * hands the stored value to part `[*]['value']` only, and nothing to the
     * part that prints `desc` raw.
     *
     * A callee with no parts gets the whole argument. So does a call that is
     * not positional: `f( ...$args )`, `array_walk()` or
     * `call_user_func_array()` hands the parameter a value inside the
     * argument, a level below the paths the parts name, and a split there
     * sent an element of the argument to the part a key of the parameter's
     * value would go to.
     *
     * @return list<array{FunctionSummary, TaintSet}>
     */
    private function argumentPieces(CallTarget $call, FunctionSummary $summary, int $index, Operand $argument): array
    {
        $whole = $this->argumentTaint($call, $summary, $index, $argument);
        $parts = $summary->partsFor($index);

        if ($parts === [] || $whole->isEmpty() || ! $call->positional) {
            return [[$summary->withoutParts(), $whole]];
        }

        // What the parameter receives besides its argument, array_reduce()'s
        // carry, and the argument's own taint, reach every part.
        $pieces = [0 => $this->state->taintOf($argument)];

        foreach ($call->moreArguments[$index] ?? [] as $more) {
            $pieces[0] = $pieces[0]->union($this->state->effectiveTaintOf($more));
        }

        $keys = $summary->keysReadFrom($index);
        self::splitByParts($this->state->shapeOf($argument), [], $parts, $keys, $pieces);

        $split = [];

        foreach ($pieces as $part => $taint) {
            if (! $taint->isEmpty()) {
                $split[] = [$summary->forPart($index, $part), $taint];
            }
        }

        return $split;
    }

    /**
     * Put each node of `$node`, which sits at `$path` in the argument, into
     * the piece of the part that covers it.
     *
     * @param list<int|string>              $path
     * @param list<list<int|string>>        $parts
     * @param list<array-key>|null          $keys  the only literal keys the callee reads at the top, if it reads
     *                                             the parameter no other way: see {@see ParameterKeyReads}
     * @param array<int, TaintSet>          $pieces
     */
    private static function splitByParts(Shape $node, array $path, array $parts, ?array $keys, array &$pieces): void
    {
        $own = $node->own();

        if (! $own->isEmpty()) {
            $part = self::coveringPart($path, $parts);
            $pieces[$part] = ($pieces[$part] ?? TaintSet::empty())->union($own);
        }

        $nodeKeys = $node->keysTaint();

        if (! $nodeKeys->isEmpty()) {
            $part = self::coveringPart([...$path, ParameterParts::KEYS], $parts);
            $pieces[$part] = ($pieces[$part] ?? TaintSet::empty())->union($nodeKeys);
        }

        foreach ($node->elements() as $key => $element) {
            // An element standing for other keys could be under any of them.
            if (Shape::isStandIn($key)) {
                foreach (self::standInSteps($key, $path, $parts, $keys) as $step) {
                    self::splitByParts($element, [...$path, $step], $parts, $keys, $pieces);
                }

                continue;
            }

            // An element the callee never reads cannot reach anything.
            if ($path === [] && $keys !== null && ! in_array($key, $keys, true)) {
                continue;
            }

            self::splitByParts($element, [...$path, ParameterParts::step($key)], $parts, $keys, $pieces);
        }

        $rest = $node->restPart();

        if (! $rest->isEmpty()) {
            self::splitByParts($rest, [...$path, ParameterParts::ANY], $parts, $keys, $pieces);
        }
    }

    /**
     * The steps an element standing for other keys, at `$path` in the
     * argument, could take into the parameter: each key a part names there
     * that the element does not leave out, and a key no part names, when the
     * callee could read one. The element's own key is never a part's step,
     * so it stands for that last one.
     *
     * @param list<int|string>       $path
     * @param list<list<int|string>> $parts
     * @param list<array-key>|null   $keys  the only literal keys the callee reads at the top: see splitByParts()
     *
     * @return list<int|string>
     */
    private static function standInSteps(string $key, array $path, array $parts, ?array $keys): array
    {
        $leftOut = Shape::leftOutBy($key) ?? [];
        $named = $path === [] && $keys !== null ? $keys : self::namedBelow($path, $parts);
        $steps = [];

        foreach ($named as $name) {
            if (! isset($leftOut[$name])) {
                $steps[] = ParameterParts::step($name);
            }
        }

        if ($path !== [] || $keys === null) {
            $steps[] = $key;
        }

        return $steps;
    }

    /**
     * The literal keys a part names directly below a node at `$path`, through
     * parts whose steps above cover `$path`.
     *
     * @param list<int|string>       $path
     * @param list<list<int|string>> $parts
     *
     * @return list<array-key>
     */
    private static function namedBelow(array $path, array $parts): array
    {
        $depth = count($path);
        $named = [];

        foreach ($parts as $part) {
            $last = count($part) === $depth + 1 ? ($part[$depth] ?? ParameterParts::ANY) : ParameterParts::ANY;

            if (in_array($last, [ParameterParts::ANY, ParameterParts::KEYS, ParameterParts::OTHERS], true)) {
                continue;
            }

            foreach ($path as $i => $at) {
                $step = $part[$i] ?? null;

                if ($step !== $at && ($step !== ParameterParts::ANY || $at === ParameterParts::KEYS)) {
                    continue 2;
                }
            }

            $named[$last] = true;
        }

        return array_keys($named);
    }

    /**
     * The part whose path covers `$path` most closely: the longest, and of
     * two as long the one with more literal keys. A step of any element covers
     * a literal key and any element, and the keys cover only the keys. Part 0,
     * the parameter's own taint, covers everything.
     *
     * @param list<int|string>       $path
     * @param list<list<int|string>> $parts
     */
    private static function coveringPart(array $path, array $parts): int
    {
        $best = 0;
        $bestScore = [-1, -1];

        foreach ($parts as $position => $part) {
            if (count($part) > count($path)) {
                continue;
            }

            $literals = 0;

            foreach ($part as $i => $step) {
                $at = $path[$i] ?? null;

                if ($step === $at) {
                    $literals += $step === ParameterParts::ANY ? 0 : 1;

                    continue;
                }

                if ($step === ParameterParts::ANY && $at !== ParameterParts::KEYS) {
                    continue;
                }

                // A literal key no part names under this node. It covers the
                // key as closely as a named one would.
                if (
                    $step === ParameterParts::OTHERS
                    && $at !== null
                    && $at !== ParameterParts::ANY
                    && $at !== ParameterParts::KEYS
                    && ! in_array($at, ParameterParts::namedUnder($parts, array_slice($part, 0, $i)), true)
                ) {
                    $literals++;

                    continue;
                }

                continue 2;
            }

            $score = [count($part), $literals];

            if ($score > $bestScore) {
                $best = $position + 1;
                $bestScore = $score;
            }
        }

        return $best;
    }

    private function argumentTaint(CallTarget $call, FunctionSummary $summary, int $index, Operand $argument): TaintSet
    {
        $keys = $call->positional ? $summary->keysReadFrom($index) : null;
        $taint = TaintSet::empty();

        // What else the parameter receives: `array_reduce()`'s carry.
        foreach ($call->moreArguments[$index] ?? [] as $more) {
            $taint = $taint->union($this->state->effectiveTaintOf($more));
        }

        if ($keys === null) {
            // A dispatcher that hands its callee each item of an array hands
            // it no key: `array_map( $cb, $items )` calls `$cb( $item )`.
            return $taint->union($call->itemsOnly
                ? $this->state->itemsTaintOf($argument)
                : $this->state->effectiveTaintOf($argument));
        }

        $taint = $taint->union($this->state->taintOf($argument))
            ->union($this->state->shapeOf($argument)->restPart()->flatten());

        foreach ($keys as $key) {
            $taint = $taint->union($this->state->shapeOf($argument)->elementAt($key)->flatten());
        }

        return $taint;
    }

    /**
     * Put a callee's returned array's elements on the call result, where a
     * read of them finds them as it would on a local array.
     *
     * A call whose result is discarded writes nothing, and one whose result a
     * dispatcher collects into an array, `array_map()`, puts it under a
     * computed key of that array, as {@see writeResult()} puts the value.
     */
    private function writeReturnedElements(Operand $result, Shape $structure, Provenance $provenance): bool
    {
        return match ($this->resultMode) {
            CallResultMode::Discard => false,
            CallResultMode::Container => $this->state->addShape($result, Shape::rest($structure), $provenance),
            CallResultMode::Value => $this->state->addShape($result, $structure, $provenance),
        };
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
                $moved = $this->argumentTaint($call, $summary, $index, $source)
                    ->intersect($summary->byRefTaintFrom($index, $target));

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

            $changed = $this->state->addShape($argument, Shape::rest(Shape::of($taint)), $provenance) || $changed;
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
        if (! $this->collecting) {
            return;
        }

        foreach ($summary->sinksFor($index) as $reference) {
            if (! $argumentTaint->has($reference->kind)) {
                continue;
            }

            // The callee's probe could only see its own body. The handler
            // shape puts the capability check in the caller and the operation
            // one helper down, so an object-id sink is re-asked here, in the
            // frame that holds the check.
            if (
                $reference->kind === TaintKind::ObjectId
                && $this->callerIsEntitled()
            ) {
                continue;
            }

            // While summarising, the sink is this function's as much as the
            // callee's: a caller two levels up learns about it only from this
            // summary. Without it `top( $_POST ) → mid( $v ) → leaf( $v ) →
            // echo` reported nothing, because `mid`'s summary said its
            // parameter reached no sink. Kept at the callee's location, which
            // is still the line that needs the fix.
            if ($this->seedParameterIndex !== null) {
                // Reached by whichever parts of this function's own parameter
                // the argument carries the kind from.
                $this->sinksReached[] = $reference->withParts($argumentTaint->partsOf($reference->kind));

                continue;
            }

            if (! $this->collectFindings) {
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

            // When the callee's own analysis of this flow was imprecise, the
            // boundary the reader needs named is the sink inside that callee,
            // so the sink step carries the mark and says so. A finding is
            // imprecise exactly when one of its steps is, so this is also what
            // keeps the reporter from ever falling back to a locationless note.
            $sinkDescription = $reference->imprecise
                ? sprintf(
                    'Reaches %s inside %s, whose own analysis of this path could not be fully '
                        . 'resolved, so the %s taint reaching it is assumed.',
                    $reference->sinkIdentity,
                    $reference->functionDisplayName,
                    $reference->kind->value,
                )
                : match ($reference->kind) {
                    TaintKind::SqlUnquoted => sprintf(
                        'Reaches %s inside %s outside quotes. The value was made safe inside quotes only, by '
                            . 'esc_sql() or an equivalent, so `1 OR 1=1` gets through. Use prepare() with a '
                            . 'placeholder.',
                        $reference->sinkIdentity,
                        $reference->functionDisplayName,
                    ),
                    TaintKind::SqlSelfQuoted => sprintf(
                        'Reaches %s inside %s inside quotes. The value brought its own quotes, which close the ones '
                            . 'around it, so its escaped part is outside any. Use prepare() with a placeholder.',
                        $reference->sinkIdentity,
                        $reference->functionDisplayName,
                    ),
                    TaintKind::SqlUnticked => sprintf(
                        'Reaches %s inside %s outside backticks. The value was made safe inside backticks only, so '
                            . 'a quote or a space in it gets through.',
                        $reference->sinkIdentity,
                        $reference->functionDisplayName,
                    ),
                    TaintKind::CsvPrefixed => sprintf(
                        'Reaches %s inside %s behind an apostrophe. The writer keeps a backslash as its escape '
                            . 'character, so a quote after one ends the cell early and starts a cell the apostrophe '
                            . 'does not cover. Pass an empty escape character.',
                        $reference->sinkIdentity,
                        $reference->functionDisplayName,
                    ),
                    default => sprintf(
                        'Reaches %s inside %s with %s taint intact.',
                        $reference->sinkIdentity,
                        $reference->functionDisplayName,
                        $reference->kind->value,
                    ),
                };

            $sinkStep = new TraceStep(
                TraceVerb::Sink,
                $reference->relativeFile,
                $reference->line,
                $reference->column,
                $reference->endColumn,
                $reference->snippet,
                $sinkDescription,
                TaintSet::of($reference->kind),
                imprecise: $reference->imprecise,
            );

            $trace = [
                ...$this->traces->build(
                    $argument,
                    $reference->kind,
                    $callStep,
                    $call->positional ? $summary->keysReadFrom($index) : null,
                ),
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
                self::traceIsImprecise($trace),
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

        $dispatcher = $this->registry->dispatcher($matcher);

        if ($dispatcher?->hook === true) {
            // A filter returns what its callbacks produced, so a value escaped
            // before the call is no longer guaranteed once it passes through.
            // An action returns nothing (returns = own): the callbacks' returns
            // are discarded, so escaping on the same line survives it. A
            // do_action() reaches output only through a by-reference argument or
            // shared state, neither of which flows through this call's return,
            // so treating it as voiding is a false positive.
            return $dispatcher->returns !== DispatchReturn::Own;
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
     *
     * An argument whose elements the result keeps under their own keys lends
     * the result its own taint only. Each element keeps its own `escaped`,
     * so `apply_filters( 'x', array( 'a' => esc_html( $v ), 'n' => 12 ) )`
     * voids `'a'` and leaves `'n'`, which nobody escaped, to the other rules.
     *
     * @param list<Operand|null> $keptInputs
     */
    private function voidEscaping(TaintSet $taint, array $keptInputs = []): TaintSet
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
        $incoming = TaintSet::empty();

        foreach ($this->voidingCall->arguments as $argument) {
            $incoming = $incoming->union(
                in_array($argument, $keptInputs, true)
                    ? $this->state->taintOf($argument)
                    : $this->state->effectiveTaintOf($argument),
            );
        }

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
    /**
     * @param list<TraceStep> $prefix
     */
    private function voidProvenance(TaintSet $taint, array $prefix = []): ?Provenance
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
            prefix: $prefix,
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
     *
     * `csv_escapable`: a writer that doubles every quote keeps each value in
     * its own cell, so an apostrophe in front of it covers all of it.
     */
    private function sinkApplies(Sink $sink, Operand $operand): bool
    {
        return match ($sink->appliesBy) {
            Sink::UNANCHORED => ! $this->anchors->has($operand),
            Sink::UNSERIALIZE_ALLOWS_OBJECTS => $this->sinkCall === null || ! $this->forbidsClasses($this->sinkCall),
            Sink::CSV_ESCAPABLE => $this->sinkCall === null || ! self::escapesEveryQuote($this->sinkCall),
            Sink::ESCAPED_THEN_VOIDED => $this->state->effectiveTaintOf($operand)->has(TaintKind::Escaped),
            // A component whose tags were stripped and whose quotes were not,
            // landing inside a quoted attribute. `html` is excluded so a raw
            // value is reported once, by the html sink, not twice.
            Sink::QUOTED_ATTRIBUTE => $this->queryShapes->quotedAttributeComponent(
                $operand,
                fn (Operand $component): bool => $this->state->effectiveTaintOf($component)->has(TaintKind::HtmlAttr)
                    && ! $this->state->effectiveTaintOf($component)->has(TaintKind::Html),
            ) !== null,
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
     * Does this `fputcsv()` call pass an empty escape character?
     *
     * Read as the fifth argument, written as a literal. PHP's default is a
     * backslash, and `"\0"` or any other character leaves the same gap for a
     * value that holds it. A named `escape:` argument is not read, because the
     * control flow graph keeps arguments by position only, so it reports.
     */
    private static function escapesEveryQuote(CallTarget $call): bool
    {
        $escape = $call->argument(4);

        return $escape !== null && OperandHelper::literalString($escape) === '';
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

            if ($sink->kind === TaintKind::CsvPrefixed && $this->sinkApplies($sink, $operand)) {
                $this->recordPrefixContext($sink, $op, $operand, $identity);
            }

            return;
        }

        if (! $this->sinkApplies($sink, $operand)) {
            return;
        }

        // An object-id sink asks about the caller, not the value: a
        // character-class guard proves the id is a number, which it was always
        // going to be, so GuardAnalyzer has nothing to say here. What
        // discharges it is a dominating check that entitles the caller to the
        // object — see {@see CapabilityGuard}.
        if ($sink->kind === TaintKind::ObjectId) {
            if ($this->callerIsEntitled()) {
                return;
            }
        } elseif ($this->proofFor($operand, $this->currentBlock)?->settlesIn($taint, $sink->kind) ?? false) {
            // Did every path here validate the value? A guard clause is how
            // careful WordPress code constrains a request value, and it lives
            // in the shape of the control flow rather than in the value, so it
            // is asked here rather than propagated. See {@see GuardAnalyzer}.
            return;
        }

        $this->recordSinkReference($sink, $op, $identity, $taint->partsOf($sink->kind));
        $this->recordQuoteContext($sink, $op, $operand, $identity);
        $this->recordPrefixContext($sink, $op, $operand, $identity);

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
            $sink->kind === TaintKind::CsvPrefixed
                ? sprintf(
                    'Reaches %s behind an apostrophe, with a backslash as the escape character. A quote after a '
                        . 'backslash ends the cell early and starts a cell the apostrophe does not cover. Pass an '
                        . 'empty escape character: fputcsv( $handle, $row, \',\', \'"\', \'\' ).',
                    $identity,
                )
                : sprintf('Reaches %s with %s taint intact.', $identity, $sink->kind->value),
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
        // Seen through any guard on the component: a check that admits spaces
        // leaves the value safe inside quotes only, as esc_sql() does.
        $unquoted = $this->queryShapes->unquotedComponent(
            $operand,
            fn (Operand $component): bool => self::guarded(
                $this->state->effectiveTaintOf($component),
                $this->proofFor($component, $this->currentBlock),
            )->has(TaintKind::SqlUnquoted),
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
                $this->state->effectiveTaintOf($unquoted)->parts(),
            );
        }

        if (! $this->collectFindings) {
            return;
        }

        // A component a guard checked on every path here is one of what the
        // guard admits, which is accounted for.
        $unaccounted = $this->queryShapes->unaccountedComponent(
            $operand,
            $this->context,
            $this->types,
            fn (Operand $component): bool => $this->guards
                ->proofFor($component, $this->currentBlock)?->clears->has(TaintKind::Sql) ?? false,
        );

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

        $unticked = $this->queryShapes->unbacktickedComponent(
            $operand,
            fn (Operand $component): bool => $this->guardedEffectiveTaintOf($component)->has(TaintKind::SqlUnticked),
        );

        if ($unticked !== null) {
            $this->emit(
                self::UNPREPARED_QUERY_RULE,
                TaintKind::Sql,
                Severity::Critical,
                $op,
                $identity,
                $unticked,
                sprintf(
                    '%s was made safe inside backticks only, by doubling or removing its backticks, and then '
                        . 'interpolated into the query passed to %s() outside them. It can still hold a quote or '
                        . 'a space. Quote it with backticks, or check it against a list of known names.',
                    OperandHelper::describe($unticked),
                    $identity,
                ),
                TaintKind::SqlUnticked,
            );
        }

        // Escaping keeps an identifier one identifier. It does not stop the
        // request choosing which: `user_pass` as readily as `post_title`. A
        // fixed list settles that, and clears `identifier` with it.
        $chosen = $this->queryShapes->backtickedComponent(
            $operand,
            fn (Operand $component): bool => $this->guardedEffectiveTaintOf($component)->has(TaintKind::Identifier),
        );

        if ($chosen !== null) {
            $this->emit(
                self::IDENTIFIER_CHOICE_RULE,
                TaintKind::Identifier,
                Severity::Medium,
                $op,
                $identity,
                $chosen,
                sprintf(
                    '%s names a column or table inside backticks in the query passed to %s(), and the request '
                        . 'chooses it. Check it against a fixed list of the names the query may use.',
                    OperandHelper::describe($chosen),
                    $identity,
                ),
            );
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
                '%s was made safe inside quotes only, by esc_sql() or an equivalent or by a check that still '
                    . 'admits spaces or operators, and then interpolated into the query passed to %s() with no '
                    . 'quotes around it. Outside quotes, `1 OR 1=1` reaches the database intact. Use prepare() '
                    . 'with a %%d or %%s placeholder.',
                OperandHelper::describe($unquoted),
                $identity,
            ),
            TaintKind::SqlUnquoted,
        );
    }

    /**
     * Where the seeded parameter lands in a query built here, for a caller
     * that escaped it first.
     *
     * The probe seeds `sql`, so the callee's query reports as a plain SQL sink.
     * A caller passing `esc_sql( $v )` carries `sql_unquoted` instead, which
     * that reference does not match, and `acme_col( esc_sql( $_GET['c'] ) )`
     * into `"SELECT $col FROM t"` went quiet. So a component carrying the seed
     * bare also records a reference for `sql_unquoted`, and one inside quotes
     * records one for `sql_self_quoted`, a value that brought its own.
     */
    private function recordQuoteContext(Sink $sink, Op $op, Operand $query, string $identity): void
    {
        if ($sink->kind !== TaintKind::Sql || $this->seedParameterIndex === null || ! $this->collecting) {
            return;
        }

        // The parameter's own flow, not other request data beside it: a query
        // that puts `$_GET['o']` bare says nothing about where the parameter
        // lands. See TaintKind::Seed.
        $carriesSql = function (Operand $component): bool {
            $taint = $this->guardedEffectiveTaintOf($component);

            return $taint->has(TaintKind::Sql) && $taint->has(TaintKind::Seed);
        };

        $contexts = [
            [TaintKind::SqlUnquoted, $this->queryShapes->unquotedComponent($query, $carriesSql)],
            [TaintKind::SqlSelfQuoted, $this->queryShapes->quotedComponent($query, $carriesSql)],
            [TaintKind::SqlUnticked, $this->queryShapes->unbacktickedComponent($query, $carriesSql)],
        ];

        foreach ($contexts as [$kind, $component]) {
            if ($component === null) {
                continue;
            }

            $this->recordSinkReference(
                new Sink($sink->matcher, $sink->arguments, $kind, Severity::Critical, self::UNPREPARED_QUERY_RULE),
                $op,
                $identity,
                $this->state->effectiveTaintOf($component)->parts(),
            );
        }
    }

    /**
     * Where the seeded parameter reaches a writer that lets a cell end early,
     * for a caller whose value, or this callee, put an apostrophe in front.
     *
     * The probe seeds `csv`. A caller that neutralised its argument passes
     * `csv_prefixed`, which a reference recorded for `csv` does not match. A
     * callee that neutralises the parameter itself reaches the sink with
     * `csv_prefixed`, which the caller's `csv` does not match. So each records
     * a reference for the other kind as well.
     */
    private function recordPrefixContext(Sink $sink, Op $op, Operand $operand, string $identity): void
    {
        if ($sink->kind !== TaintKind::CsvPrefixed || $this->seedParameterIndex === null || ! $this->collecting) {
            return;
        }

        $taint = $this->guardedEffectiveTaintOf($operand);

        if (! $taint->has(TaintKind::Seed)) {
            return;
        }

        [$held, $other] = $taint->has(TaintKind::CsvPrefixed)
            ? [TaintKind::CsvPrefixed, TaintKind::Csv]
            : [TaintKind::Csv, TaintKind::CsvPrefixed];

        if (! $taint->has($held)) {
            return;
        }

        $this->recordSinkReference(
            new Sink($sink->matcher, $sink->arguments, $other, $sink->severity, $sink->ruleId),
            $op,
            $identity,
            $taint->partsOf($held),
        );
    }

    /**
     * An operand's taint by every route, less what a guard dominating this
     * block proves.
     */
    private function guardedEffectiveTaintOf(Operand $operand): TaintSet
    {
        return self::guarded(
            $this->state->effectiveTaintOf($operand),
            $this->proofFor($operand, $this->currentBlock),
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
    private function recordPropertyReference(?string $class, string $property, Shape $value): void
    {
        if ($this->seedParameterIndex === null || $value->isEmpty()) {
            return;
        }

        $id = strtolower($class ?? '?') . '::' . $property;
        $joined = ($this->propertiesReached[$id][2] ?? Shape::empty())->join($value);
        $this->propertiesReached[$id] = [$class, $property, $joined];
    }

    /**
     * @param int $parts the parts of the seeded parameter that carry the
     *                   sink's kind here: see {@see TaintSet::partsOf()}
     */
    private function recordSinkReference(Sink $sink, Op $op, string $identity, int $parts = TaintSet::EVERY_PART): void
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
            $parts === 0 ? TaintSet::EVERY_PART : $parts,
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

    /**
     * @param TaintKind|null $traceKind the kind the trace follows, when the finding's
     *                                  kind is not the one that reached the sink: an
     *                                  escaped value used unquoted is an `sql` finding
     *                                  that `sql_unquoted` reached
     */
    private function emit(
        string $ruleId,
        TaintKind $kind,
        Severity $severity,
        Op $op,
        string $identity,
        Operand $operand,
        string $sinkDescription,
        ?TaintKind $traceKind = null,
    ): void {
        $position = OperandHelper::position($op, $this->context->file->sourceMap);
        $snippet = trim($this->context->file->sourceMap->line($position['line']));

        $key = implode('|', [$ruleId, $kind->value, (string) $position['line'], (string) $position['column']]);

        if (isset($this->emitted[$key])) {
            return;
        }

        $this->emitted[$key] = true;

        $sinkStep = $this->traces->sinkStep($op, TaintSet::of($kind), $sinkDescription);
        $trace = $this->traces->build($operand, $traceKind ?? $kind, $sinkStep);

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
            self::traceIsImprecise($trace),
            $identity,
        );
    }

    /**
     * Whether this finding's own path crossed something unresolved.
     *
     * Path-level, not function-level: a finding is imprecise when one of the
     * steps on its own trace is, not when its function happened to contain an
     * unresolvable construct somewhere else. In a plugin of thousand-line
     * methods, the difference is most of the flags.
     *
     * @param list<TraceStep> $trace
     */
    private static function traceIsImprecise(array $trace): bool
    {
        foreach ($trace as $step) {
            if ($step->imprecise) {
                return true;
            }
        }

        return false;
    }
}
