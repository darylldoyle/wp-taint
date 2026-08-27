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
        $this->keyedTaint = new SplObjectStorage();
        $this->keyedProvenance = new SplObjectStorage();
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
    /**
     * Taint written into one constant key of an array.
     *
     * ```php
     * $context['title'] = $_GET['title'];
     * $context['id']    = 42;
     * echo $context['id'];              // was reported, and should not be
     * ```
     *
     * Kept beside the whole-array slot rather than replacing it, because both
     * answers are needed: a write with a literal key is precise, a write with a
     * computed key can land anywhere, and a read with a computed key has to see
     * everything.
     *
     * It only helps when *both* the write and the read name a constant key. The
     * moment either is dynamic the whole-array slot takes over, which is what
     * the analysis did for every array until now.
     *
     * Keys are `array-key`, not `string`: PHP silently converts a numeric
     * string key to an int on storage, so `$a['0']` and `$a[0]` are one slot
     * and a read hands back an int. Typing these as `string` crashed on the
     * first plugin that used a numeric key.
     *
     * @var SplObjectStorage<Operand, array<array-key, TaintSet>>
     */
    private SplObjectStorage $keyedTaint;

    /** @var SplObjectStorage<Operand, array<array-key, Provenance>> */
    private SplObjectStorage $keyedProvenance;

    public function keyedTaintOf(Operand $operand, string|int $key): TaintSet
    {
        $keys = $this->keyedTaint[$operand] ?? [];

        return $keys[$key] ?? TaintSet::empty();
    }

    /**
     * Everything written into any constant key, for a read that names none.
     */
    public function allKeyedTaintOf(Operand $operand): TaintSet
    {
        $set = TaintSet::empty();

        foreach ($this->keyedTaint[$operand] ?? [] as $taint) {
            $set = $set->union($taint);
        }

        return $set;
    }

    /**
     * Every keyed slot of an operand, for handing an array across a boundary.
     *
     * @return array<array-key, TaintSet>
     */
    public function keyedTaintMapOf(Operand $operand): array
    {
        return $this->keyedTaint[$operand] ?? [];
    }

    public function keyedProvenanceOf(Operand $operand, string|int $key): ?Provenance
    {
        $keys = $this->keyedProvenance[$operand] ?? [];

        return $keys[$key] ?? null;
    }

    public function addKeyedTaint(Operand $operand, string|int $key, TaintSet $taint, Provenance $provenance): bool
    {
        if ($taint->isEmpty()) {
            return false;
        }

        $keys = $this->keyedTaint[$operand] ?? [];
        $existing = $keys[$key] ?? TaintSet::empty();
        $merged = $existing->union($taint);

        if ($merged->equals($existing)) {
            return false;
        }

        $keys[$key] = $merged;
        $this->keyedTaint[$operand] = $keys;

        $provenances = $this->keyedProvenance[$operand] ?? [];
        $provenances[$key] = $provenance;
        $this->keyedProvenance[$operand] = $provenances;

        return true;
    }

    /**
     * Copy every keyed slot from one operand to another, for `$b = $a`.
     *
     * @return bool whether anything changed
     */
    public function copyKeyedTaint(Operand $from, Operand $to): bool
    {
        $changed = false;

        foreach ($this->keyedTaint[$from] ?? [] as $key => $taint) {
            $provenance = $this->keyedProvenanceOf($from, $key);

            if ($provenance !== null) {
                $changed = $this->addKeyedTaint($to, $key, $taint, $provenance) || $changed;
            }
        }

        return $changed;
    }

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
    /**
     * Everything this value carries, by any route.
     *
     * All three slots, including the per-key ones. Anywhere a value crosses a
     * boundary that cannot carry keys — passed to a function, reached by a
     * sink, handed to an include — the precise answer is unavailable and the
     * whole of it has to travel.
     *
     * Leaving the keyed slots out of this was a false negative and a bad one:
     * `wpforms_panel_field( …, [ 'default' => $this->form->post_title ] )` put
     * the taint under one key, `effectiveTaintOf()` reported the array clean,
     * and the flow disappeared at the call. Findings went *down* on the corpus,
     * which is not the same as going right.
     *
     * Only {@see keyedTaintOf()} answers narrowly, and only a read that names a
     * constant key may ask it.
     */
    public function effectiveTaintOf(Operand $operand): TaintSet
    {
        return $this->taintOf($operand)
            ->union($this->containerTaintOf($operand))
            ->union($this->allKeyedTaintOf($operand));
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
     * Union of the taint written into several operands *as containers*.
     *
     * Kept separate from {@see unionOf()} so that a value flowing through a
     * pass-through does not have its element taint promoted into its own slot.
     * Promoting it put two ops into disagreement over the same operand — one
     * computing the own slot, the other the union — and the fixed point
     * oscillated.
     *
     * @param list<Operand|null> $operands
     */
    public function unionOfContainers(array $operands): TaintSet
    {
        $set = TaintSet::empty();

        foreach ($operands as $operand) {
            if ($operand !== null) {
                $set = $set->union($this->containerTaintOf($operand));
            }
        }

        return $set;
    }

    /**
     * Union of the operands' own taint, ignoring anything written into them as
     * containers.
     *
     * @param list<Operand|null> $operands
     */
    public function unionOfOwn(array $operands): TaintSet
    {
        $set = TaintSet::empty();

        foreach ($operands as $operand) {
            if ($operand !== null) {
                $set = $set->union($this->taintOf($operand));
            }
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
