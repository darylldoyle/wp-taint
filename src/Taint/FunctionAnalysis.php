<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Fingerprint;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Registry\ArgumentSelector;
use Enshrined\WpTaint\Registry\Matcher;
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

    private TaintState $state;

    private ClassTypeMap $types;

    /** @var list<Finding> */
    private array $findings = [];

    /** @var list<SinkReference> */
    private array $sinksReached = [];

    /** @var array<string, true> */
    private array $emitted = [];

    private TaintSet $returnTaint;

    private bool $imprecise = false;

    /** @var list<AnalysisWarning> */
    private array $warnings = [];

    private readonly QueryShapeInspector $queryShapes;

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
        private readonly AnalysisOptions $options,
        private readonly ?int $seedParameterIndex,
        private readonly bool $collectFindings,
    ) {
        $this->state = new TaintState();
        $this->types = new ClassTypeMap();
        $this->queryShapes = new QueryShapeInspector(
            $literals,
            new OriginClassifier($registry, $resolver, $properties),
        );
        $this->returnTaint = TaintSet::empty();
        $this->blocks = BlockOrder::of($this->context->func->cfg);
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

        $iterations = 0;

        do {
            $changed = $this->pass();
            $iterations++;
        } while ($changed && $iterations < $this->options->maxIterations);

        if ($changed) {
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
            $this->warnings,
            $this->state,
        );
    }

    /**
     * Superglobals are the only sources that are not calls, so they are seeded
     * up front by walking every operand the function mentions.
     */
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

        foreach ($this->blocks as $block) {
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

        return $changed;
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

        $merged = $this->state->unionOf($incoming);

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
            $op instanceof Op\Iterator\Value => $this->transferContainerRead(
                $op,
                $op->var,
                'Iterating a tainted collection yields tainted values.',
            ),
            // Keys, not values: `foreach ( $_GET as $k => $v )` has an
            // attacker-controlled key, but `foreach ( $rows as $k => $v )` after
            // `$rows[$i] = $tainted` does not.
            $op instanceof Op\Iterator\Key => $this->transferPassThrough(
                $op,
                $op->var,
                'Keys of an attacker-controlled collection are attacker-controlled too.',
            ),
            // `isset($x)` and `!empty($x)` narrow a value's *type*; they do not
            // change its taint. php-cfg gives the assertion an operand that is
            // already written by the op producing the value, so zeroing it here
            // both launders taint and makes the fixed point oscillate forever
            // between the two writers.
            $op instanceof Op\Expr\Assertion => $this->transferPassThrough(
                $op,
                $op->expr,
                'An isset() or empty() guard narrows the type but does not escape the value.',
            ),
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
        $value = $op->expr;
        $taint = $this->state->taintOf($value);

        $provenance = new Provenance(
            TraceVerb::Propagate,
            $op,
            sprintf('Assigned to %s.', OperandHelper::describe($op->var)),
            [$value],
        );

        $changed = $this->state->set($op->var, $taint, $provenance);
        $changed = $this->state->set($op->result, $taint, $provenance) || $changed;

        // `$a = $b` where `$b` is an array with taint written into its elements
        // has to carry that across, or the taint is lost at the assignment.
        $container = $this->state->containerTaintOf($value);

        if (! $container->isEmpty()) {
            $changed = $this->state->addContainerTaint($op->var, $container, $provenance) || $changed;
            $changed = $this->state->addContainerTaint($op->result, $container, $provenance) || $changed;
        }

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
            }
        }

        if ($taint->isEmpty()) {
            return false;
        }

        if ($target instanceof Op\Expr\ArrayDimFetch) {
            // Over-approximate: the whole array becomes tainted, not just the
            // written key. Recorded in KNOWN_LIMITATIONS.md.
            //
            // Held in a separate slot from the operand's own taint, because SSA
            // does not re-version an array for an element write: `$a = array();`
            // and `$a[$k] = $tainted;` write the same operand, and letting them
            // share a slot makes the fixed point oscillate.
            return $this->state->addContainerTaint(
                $target->var,
                $taint,
                new Provenance(
                    TraceVerb::Propagate,
                    $op,
                    sprintf(
                        'Written into %s. Array taint is tracked per array, not per key, so the whole array is '
                            . 'treated as tainted from here.',
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

        return $this->transferContainerRead(
            $op,
            $op->var,
            sprintf('Read out of %s.', OperandHelper::describe($op->var)),
        );
    }

    /**
     * A read out of a container: its own taint plus anything written into it
     * through an element.
     */
    private function transferContainerRead(Op\Expr $op, Operand $container, string $description): bool
    {
        // A read out of a container flattens both slots: the value that comes
        // out carries whatever was put in, however it got there.
        $taint = $this->state->effectiveTaintOf($container);

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

    private function propertyOwnerClass(Op\Expr\PropertyFetch $fetch): ?string
    {
        $receiver = OperandHelper::variableName($fetch->var);

        if ($receiver === 'this') {
            return $this->context->className;
        }

        return $this->types->classOf($fetch->var);
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

        $valueTaint = $this->state->unionOf($values);

        if ($valueTaint->isEmpty()) {
            return $changed;
        }

        return $this->state->addContainerTaint(
            $op->result,
            $valueTaint,
            new Provenance(TraceVerb::Propagate, $op, 'Placed into an array literal.', $values),
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

    private function transferPassThrough(Op\Expr $op, Operand $input, string $description): bool
    {
        return $this->transferUnion($op, [$input], $description);
    }

    private function transferReturn(Op\Terminal\Return_ $op): bool
    {
        if ($op->expr === null) {
            return false;
        }

        $taint = $this->state->taintOf($op->expr);
        $merged = $this->returnTaint->union($taint);
        $changed = ! $merged->equals($this->returnTaint);
        $this->returnTaint = $merged;

        return $changed;
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

        // The included file is not followed across the CFG; see
        // KNOWN_LIMITATIONS.md. The result of an include is whatever the
        // included file returned, which we cannot know.
        return $this->state->set($op->result, TaintSet::empty());
    }

    private function transferConstructSink(Op\Expr $op, string $construct, Operand $operand): bool
    {
        $this->checkConstructSink($op, $construct, $operand);

        return $this->state->set($op->result, TaintSet::empty());
    }

    private function checkConstructSink(Op $op, string $construct, Operand $operand): void
    {
        $sink = $this->registry->sink(Matcher::construct($construct));

        if ($sink === null) {
            return;
        }

        $this->reportSink($sink, $op, $operand, $construct);
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
    private function writeResult(Operand $result, TaintSet $taint, ?Provenance $provenance = null): bool
    {
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

        if ($matcher !== null) {
            $sink = $this->registry->sink($matcher);

            if ($sink !== null) {
                $this->reportCallSink($sink, $op, $call, $matcher);
            }

            $sanitizer = $this->registry->sanitizer($matcher);

            if ($sanitizer !== null) {
                return $this->transferSanitizer($op, $call, $sanitizer, $matcher);
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
                );
            }

            $propagator = $this->registry->propagator($matcher);

            if ($propagator !== null) {
                return $this->transferPropagator($op, $call, $propagator->arguments, $matcher, $propagator->note);
            }

            if ($this->registry->isSafeCall($matcher)) {
                return $this->writeResult($op->result, TaintSet::empty());
            }

            if ($sink !== null) {
                // A sink with no other role consumes the value; whatever it
                // returns is not derived from the tainted argument in a way we
                // model.
                return $this->writeResult($op->result, TaintSet::empty());
            }
        }

        if ($this->options->interprocedural && $call->userFunctionKey !== null) {
            return $this->transferUserCall($op, $call);
        }

        if ($call->userFunctionKey !== null) {
            // --no-interprocedural: user calls are opaque, which is exactly the
            // Phase 3 behaviour this flag exists to reproduce.
            return $this->writeResult($op->result, TaintSet::empty());
        }

        // A named function the catalogue has no model for. Returning clean is
        // the deliberate choice: a documented false negative beats an
        // undocumented false positive.
        return $this->writeResult($op->result, TaintSet::empty());
    }

    private function sourceApplies(Source $source, CallTarget $call): bool
    {
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

            $this->emit(
                $ruleId,
                $kind,
                $this->registry->severityForRule($ruleId, Severity::Critical),
                $op,
                $matcher->identity(),
                $formatArgument,
                sprintf(
                    '%s cannot protect a format string that is itself built from a variable.',
                    $matcher->describe(),
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

        foreach ($call->arguments as $index => $argument) {
            // Both slots: the callee receives the whole value, and an array
            // passed in arrives with its elements attached. Reading only the
            // own slot loses every flow through `f( array( $_GET['v'] ) )`.
            $argumentTaint = $this->state->effectiveTaintOf($argument);

            if ($argumentTaint->isEmpty()) {
                continue;
            }

            $returned = $argumentTaint->intersect($summary->returnTaintFor($index));

            if (! $returned->isEmpty()) {
                $result = $result->union($returned);
                $contributors[] = $argument;
                $viaParameters[] = $index;
            }

            $this->reportSummarySinks($op, $call, $summary, $index, $argument, $argumentTaint);
        }

        if ($result->isEmpty()) {
            return $this->writeResult($op->result, $result);
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
        );
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

    private function reportCallSink(Sink $sink, Op $op, CallTarget $call, Matcher $matcher): void
    {
        foreach ($sink->arguments->resolve($call->argumentCount()) as $index) {
            $argument = $call->argument($index);

            if ($argument === null) {
                continue;
            }

            $this->reportSink($sink, $op, $argument, $matcher->identity());
        }
    }

    private function reportSink(Sink $sink, Op $op, Operand $operand, string $identity): void
    {
        $taint = $this->state->effectiveTaintOf($operand);

        if (! $taint->has($sink->kind)) {
            $this->checkQueryShape($sink, $op, $operand, $identity);

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
        if (! $this->collecting || ! $this->collectFindings || $sink->kind !== TaintKind::Sql) {
            return;
        }

        $unaccounted = $this->queryShapes->unaccountedComponent($operand, $this->context, $this->types);

        if ($unaccounted === null) {
            return;
        }

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
    }

    /**
     * Record that the seeded parameter reached a sink, for the caller's
     * benefit. Only meaningful while summarising.
     */
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

        $this->findings[] = new Finding(
            $ruleId,
            $this->registry->rule($ruleId),
            $severity,
            $kind,
            $this->context->file->relativePath,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            $this->registry->ruleMessage($ruleId),
            $this->traces->build($operand, $kind, $sinkStep),
            Fingerprint::compute($ruleId, $this->context->file->relativePath, $identity, $snippet),
            $this->imprecise,
            $identity,
        );
    }
}
