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
        $steps = [];

        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();
        $current = $operand;

        while ($current !== null && ! $seen->contains($current) && count($steps) < $this->maxSteps) {
            $seen->attach($current);

            // A value whose taint is all in its elements has no provenance of
            // its own. The write into the elements says where it came from.
            $provenance = $this->state->provenanceOf($current)
                ?? $this->state->containerProvenanceOf($current)
                ?? $this->elementProvenance($current, $kind, $keys);

            if ($provenance === null) {
                break;
            }

            $steps[] = $this->stepFor($provenance, $current, $kind);

            // A property read has no predecessor in this function's def-use
            // graph: the write happened in another body. The recorded write
            // trace goes in ahead of it so the finding still reaches a source.
            if ($provenance->prefix !== []) {
                $steps = [...$steps, ...array_reverse($provenance->prefix)];

                break;
            }

            [$current, $keys] = $this->nextOperand($provenance, $kind);
        }

        $steps = array_reverse($steps);
        $steps[] = $sinkStep;

        return array_values($steps);
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
     * Follow the predecessor that actually carries the kind being traced.
     *
     * A concatenation of a clean string and a tainted one has two predecessors;
     * following the clean one produces a trace that stops short of the source
     * and teaches the reader nothing.
     *
     * @return array{0: Operand|null, 1: list<array-key>|null} the predecessor, and
     *                                                         the elements of it
     *                                                         the flow can come from
     */
    private function nextOperand(Provenance $provenance, TaintKind $kind): array
    {
        foreach ($provenance->predecessors as $position => $predecessor) {
            if ($this->state->taintOf($predecessor)->has($kind)) {
                return [$predecessor, $provenance->predecessorKeys[$position] ?? null];
            }
        }

        return [$provenance->predecessors[0] ?? null, $provenance->predecessorKeys[0] ?? null];
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
