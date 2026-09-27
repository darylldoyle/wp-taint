<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\SourceMap;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Reconstructs the source-to-sink path by walking provenance links backwards.
 *
 * Every finding carries a trace. No exceptions — a finding without one is a
 * finding nobody can triage.
 */
final class TraceBuilder
{
    /**
     * How many values a trace may look at for each step it can hold. A walk
     * that backs out of loops could otherwise visit most of a large function
     * for one finding.
     */
    private const VISITS_PER_STEP = 4;

    public function __construct(
        private readonly TaintState $state,
        private readonly SourceMap $sourceMap,
        private readonly string $relativeFile,
        private readonly int $maxSteps,
    ) {
    }

    /**
     * @param list<array-key>|null $keys the elements of the operand the flow
     *                                   can come from, when it cannot come
     *                                   from all of them: a callee that reads
     *                                   its parameter only through those keys
     *
     * @return list<TraceStep>
     */
    public function build(Operand $operand, TaintKind $kind, TraceStep $sinkStep, ?array $keys = null): array
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();
        $longest = [];
        $budget = self::VISITS_PER_STEP * $this->maxSteps;

        $steps = $this->search($operand, $keys, $kind, $seen, [], $longest, $budget) ?? $longest;
        $steps = array_reverse($steps);
        $steps[] = $sinkStep;

        return array_values($steps);
    }

    /**
     * Walk back from an operand to where its taint starts.
     *
     * The walk tries the predecessors that carry the kind, in order, and backs
     * out of any that lead nowhere. Taking only the first was not enough. In a
     * loop the first is often the value from the last time round, which the
     * walk has already passed, so the trace stopped at a join with no source.
     *
     * A walk ends well at a step with no predecessor, where the flow starts, or
     * at a step that brings its own earlier trace. It ends badly at a value
     * with no provenance or one it has already passed. When no walk ends well,
     * the longest one is the trace.
     *
     * @param list<array-key>|null            $keys
     * @param SplObjectStorage<Operand, true> $seen
     * @param list<TraceStep>                 $walked  steps so far, sink side first
     * @param list<TraceStep>                 $longest the longest walk that ended badly
     *
     * @return list<TraceStep>|null the steps, sink side first, or null when this walk ended badly
     */
    private function search(
        ?Operand $current,
        ?array $keys,
        TaintKind $kind,
        SplObjectStorage $seen,
        array $walked,
        array &$longest,
        int &$budget,
    ): ?array {
        if ($current === null || $seen->contains($current) || count($walked) >= $this->maxSteps || $budget <= 0) {
            return $this->endedBadly($walked, $longest);
        }

        $seen->attach($current);
        $budget--;

        // A value whose taint is all in its elements has no provenance of
        // its own. The write into the elements says where it came from.
        $provenance = $this->state->provenanceOf($current)
            ?? $this->state->containerProvenanceOf($current)
            ?? $this->elementProvenance($current, $kind, $keys);

        if ($provenance === null) {
            return $this->endedBadly($walked, $longest);
        }

        $walked[] = $this->stepFor($provenance, $current, $kind);

        // A property read has no predecessor in this function's def-use
        // graph: the write happened in another body. The recorded write
        // trace goes in ahead of it so the finding still reaches a source.
        if ($provenance->prefix !== []) {
            return [...$walked, ...array_reverse($provenance->prefix)];
        }

        $predecessors = $this->nextOperands($provenance, $kind);

        // Nothing before this step carries the kind, so the flow starts here.
        if ($predecessors === []) {
            return $walked;
        }

        foreach ($predecessors as [$next, $nextKeys, $nextKind]) {
            $found = $this->search($next, $nextKeys, $nextKind, $seen, $walked, $longest, $budget);

            if ($found !== null) {
                return $found;
            }
        }

        return $this->endedBadly($walked, $longest);
    }

    /**
     * @param list<TraceStep> $walked
     * @param list<TraceStep> $longest
     */
    private function endedBadly(array $walked, array &$longest): null
    {
        if (count($walked) > count($longest)) {
            $longest = $walked;
        }

        return null;
    }

    /**
     * The provenance of the first element carrying the kind being traced.
     *
     * @param list<array-key>|null $keys
     */
    private function elementProvenance(Operand $operand, TaintKind $kind, ?array $keys): ?Provenance
    {
        foreach ($this->state->keyedTaintMapOf($operand) as $key => $taint) {
            if ($taint->has($kind) && ($keys === null || in_array($key, $keys, true))) {
                return $this->state->keyedProvenanceOf($operand, $key);
            }
        }

        return null;
    }

    private function stepFor(Provenance $provenance, Operand $operand, TaintKind $kind): TraceStep
    {
        $position = OperandHelper::position($provenance->op, $this->sourceMap);

        unset($kind);

        return new TraceStep(
            $provenance->verb,
            $this->relativeFile,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            trim($this->sourceMap->line($position['line'])),
            $provenance->description,
            $this->state->taintOf($operand),
            $provenance->callee,
            $provenance->parameterIndex,
            $provenance->imprecise,
        );
    }

    /**
     * The predecessors to follow: those that carry the kind being traced, in
     * source order.
     *
     * A concatenation of a clean string and a tainted one has two predecessors;
     * following the clean one produces a trace that stops short of the source
     * and teaches the reader nothing. The kind counts wherever the predecessor
     * holds it, in its elements too, so `implode( ',', $row )` leads to `$row`.
     *
     * When none carries it, the step is where the kind began. A kind derived
     * from another began from that one: `esc_sql()` turns `sql` into
     * `sql_unquoted`, and a filter turns `escaped` into `escape_voided`. So the
     * walk goes on upstream following the parent kind. A payload kind that
     * begins here began here, as in a summary whose return carries `html`
     * whatever its argument. Walking on into that argument named a source the
     * `html` never came from.
     *
     * @return list<array{0: Operand, 1: list<array-key>|null, 2: TaintKind}> each
     *                                                                     predecessor,
     *                                                                     the elements of
     *                                                                     it the flow can
     *                                                                     come from, and
     *                                                                     the kind to follow
     */
    private function nextOperands(Provenance $provenance, TaintKind $kind): array
    {
        $next = $this->carrying($provenance, $kind, $kind);

        if ($next !== [] || ! $kind->isDerived()) {
            return $next;
        }

        foreach (self::parentsOf($kind) as $parent) {
            $next = $this->carrying($provenance, $parent, $parent);

            if ($next !== []) {
                return $next;
            }
        }

        $first = $provenance->predecessors[0] ?? null;

        return $first === null ? [] : [[$first, $provenance->predecessorKeys[0] ?? null, $kind]];
    }

    /**
     * @return list<array{0: Operand, 1: list<array-key>|null, 2: TaintKind}>
     */
    private function carrying(Provenance $provenance, TaintKind $held, TaintKind $follow): array
    {
        $next = [];

        foreach ($provenance->predecessors as $position => $predecessor) {
            if ($this->state->effectiveTaintOf($predecessor)->has($held)) {
                $next[] = [$predecessor, $provenance->predecessorKeys[$position] ?? null, $follow];
            }
        }

        return $next;
    }

    /**
     * The kinds a derived kind is made from.
     *
     * @return list<TaintKind>
     */
    private static function parentsOf(TaintKind $kind): array
    {
        return match ($kind) {
            TaintKind::SqlUnquoted => [TaintKind::Sql],
            TaintKind::EscapeVoided => [TaintKind::Escaped, TaintKind::Html],
            TaintKind::Escaped => [TaintKind::Html],
            default => [],
        };
    }

    /**
     * The final step of every trace.
     */
    public function sinkStep(?Op $op, TaintSet $kinds, string $description): TraceStep
    {
        $position = OperandHelper::position($op, $this->sourceMap);

        return new TraceStep(
            TraceVerb::Sink,
            $this->relativeFile,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            trim($this->sourceMap->line($position['line'])),
            $description,
            $kinds,
        );
    }

    public function step(
        TraceVerb $verb,
        ?Op $op,
        TaintSet $kinds,
        string $description,
        ?string $callee = null,
        ?int $parameterIndex = null,
    ): TraceStep {
        $position = OperandHelper::position($op, $this->sourceMap);

        return new TraceStep(
            $verb,
            $this->relativeFile,
            $position['line'],
            $position['column'],
            $position['endColumn'],
            trim($this->sourceMap->line($position['line'])),
            $description,
            $kinds,
            $callee,
            $parameterIndex,
        );
    }
}
