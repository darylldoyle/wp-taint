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
     * @return list<TraceStep>
     */
    public function build(Operand $operand, TaintKind $kind, TraceStep $sinkStep): array
    {
        $steps = [];

        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();
        $current = $operand;

        while ($current !== null && ! $seen->contains($current) && count($steps) < $this->maxSteps) {
            $seen->attach($current);

            $provenance = $this->state->provenanceOf($current);

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

            $current = $this->nextOperand($provenance, $kind);
        }

        $steps = array_reverse($steps);
        $steps[] = $sinkStep;

        return array_values($steps);
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
     */
    private function nextOperand(Provenance $provenance, TaintKind $kind): ?Operand
    {
        foreach ($provenance->predecessors as $predecessor) {
            if ($this->state->taintOf($predecessor)->has($kind)) {
                return $predecessor;
            }
        }

        return $provenance->predecessors[0] ?? null;
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
