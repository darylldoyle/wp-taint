<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Taint for the operands of one function body, plus the provenance needed to
 * reconstruct a trace.
 *
 * Keyed by operand identity rather than by name: SSA gives every definition its
 * own operand object, and that is exactly the granularity taint wants.
 */
final class TaintState
{
    /** @var SplObjectStorage<Operand, TaintSet> */
    private SplObjectStorage $taint;

    /** @var SplObjectStorage<Operand, Provenance> */
    private SplObjectStorage $provenance;

    public function __construct()
    {
        $this->taint = new SplObjectStorage();
        $this->provenance = new SplObjectStorage();
    }

    public function taintOf(Operand $operand): TaintSet
    {
        if (! $this->taint->contains($operand)) {
            return TaintSet::empty();
        }

        return $this->taint[$operand];
    }

    /**
     * Union of the taint of several operands, e.g. the inputs to a concat.
     *
     * @param list<Operand|null> $operands
     */
    public function unionOf(array $operands): TaintSet
    {
        $set = TaintSet::empty();

        foreach ($operands as $operand) {
            if ($operand === null) {
                continue;
            }

            $set = $set->union($this->taintOf($operand));
        }

        return $set;
    }

    /**
     * Record the taint of an operand.
     *
     * Returns true when the value changed, which is how the fixed point knows
     * to keep going. Transfer functions are monotone in their inputs, so
     * replacing rather than widening is safe here — and it is what lets a
     * sanitizer actually reduce a set.
     */
    public function set(Operand $operand, TaintSet $taint, ?Provenance $provenance = null): bool
    {
        $changed = ! $this->taintOf($operand)->equals($taint);

        $this->taint[$operand] = $taint;

        if ($provenance !== null && ! $taint->isEmpty()) {
            $this->provenance[$operand] = $provenance;
        }

        return $changed;
    }

    /**
     * Add taint without removing what is already there. Used for array writes,
     * where the whole array is over-approximated as tainted.
     */
    public function add(Operand $operand, TaintSet $taint, ?Provenance $provenance = null): bool
    {
        return $this->set($operand, $this->taintOf($operand)->union($taint), $provenance);
    }

    public function provenanceOf(Operand $operand): ?Provenance
    {
        if (! $this->provenance->contains($operand)) {
            return null;
        }

        return $this->provenance[$operand];
    }

    public function hasProvenance(Operand $operand): bool
    {
        return $this->provenance->contains($operand);
    }
}
