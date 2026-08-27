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

    /** @var SplObjectStorage<Operand, TaintSet> */
    private SplObjectStorage $containerTaint;

    /** @var SplObjectStorage<Operand, Provenance> */
    private SplObjectStorage $containerProvenance;

    public function __construct()
    {
        $this->taint = new SplObjectStorage();
        $this->provenance = new SplObjectStorage();
        $this->containerTaint = new SplObjectStorage();
        $this->containerProvenance = new SplObjectStorage();
    }

    /**
     * Taint written into an array *through an element*, tracked separately from
     * the operand's own taint.
     *
     * `$out = array(); $out[$k] = $tainted;` writes both to the same SSA
     * operand: SSA does not re-version a variable for an element write. Folding
     * the element taint into the operand's own slot means the assignment and
     * the element write fight over it, one setting it empty and the other
     * setting it tainted, and the fixed point oscillates forever. That shape —
     * build an empty array, fill it in a loop — is everywhere in plugin code.
     *
     * Keeping the two apart makes both transfer functions monotone, which is
     * what the fixed point needs to terminate.
     */
    public function containerTaintOf(Operand $operand): TaintSet
    {
        if (! $this->containerTaint->contains($operand)) {
            return TaintSet::empty();
        }

        return $this->containerTaint[$operand];
    }

    public function addContainerTaint(Operand $operand, TaintSet $taint, Provenance $provenance): bool
    {
        if ($taint->isEmpty()) {
            return false;
        }

        $merged = $this->containerTaintOf($operand)->union($taint);

        if ($merged->equals($this->containerTaintOf($operand))) {
            return false;
        }

        $this->containerTaint[$operand] = $merged;
        $this->containerProvenance[$operand] = $provenance;

        return true;
    }

    /**
     * An operand's own taint plus anything written into it as a container.
     */
    public function effectiveTaintOf(Operand $operand): TaintSet
    {
        return $this->taintOf($operand)->union($this->containerTaintOf($operand));
    }

    public function containerProvenanceOf(Operand $operand): ?Provenance
    {
        if (! $this->containerProvenance->contains($operand)) {
            return null;
        }

        return $this->containerProvenance[$operand];
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

            $set = $set->union($this->effectiveTaintOf($operand));
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
