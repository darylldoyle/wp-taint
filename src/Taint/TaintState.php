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
     *
     * A write under a literal key lands in that key's element, and anything
     * else in the rest: see {@see Shape}.
     *
     * ```php
     * $context['title'] = $_GET['title'];
     * $context['id']    = 42;
     * echo $context['id'];              // was reported, and should not be
     * ```
     *
     * Both answers are needed: a write with a literal key is precise, a write
     * with a computed key can land anywhere, and a read with a computed key has
     * to see everything. A key-by-key answer helps only when *both* the write
     * and the read name a constant key. The moment either is dynamic the rest
     * takes over, which is what the analysis did for every array until the
     * per-key answer came in.
     *
     * Keys are `array-key`, not `string`: PHP silently converts a numeric
     * string key to an int on storage, so `$a['0']` and `$a[0]` are one element
     * and a read hands back an int. Typing these as `string` crashed on the
     * first plugin that used a numeric key.
     *
     * @var SplObjectStorage<Operand, Shape>
     */
    private SplObjectStorage $shapes;

    /**
     * The shape last joined into each operand, as it was handed in. Shapes
     * only grow, so the same one again adds nothing, and every pass of the
     * fixed point hands most operands the same shape.
     *
     * @var SplObjectStorage<Operand, Shape>
     */
    private SplObjectStorage $lastJoined;

    private bool $countsChanges = false;

    /** @var SplObjectStorage<Operand, int> */
    private SplObjectStorage $changeCounts;

    public function __construct()
    {
        $this->taint = new SplObjectStorage();
        $this->provenance = new SplObjectStorage();
        $this->shapes = new SplObjectStorage();
        $this->lastJoined = new SplObjectStorage();
        $this->changeCounts = new SplObjectStorage();
    }

    /**
     * What was written into an operand through its elements. Its own taint is
     * not part of it: see {@see taintOf()}.
     */
    public function shapeOf(Operand $operand): Shape
    {
        if (! $this->shapes->contains($operand)) {
            return Shape::empty();
        }

        return $this->shapes[$operand];
    }

    /**
     * An operand as one shape: its own taint on top, its parts below.
     *
     * What an array literal or a merge hands on, so a value placed into an
     * element keeps its parts rather than folding them into one set.
     */
    public function valueShapeOf(Operand $operand): Shape
    {
        return Shape::node($this->taintOf($operand), $this->shapeOf($operand));
    }

    /**
     * Join `$shape` into what was written into an operand's elements.
     *
     * Grow-only, like every element write: see {@see $shapes}. `$provenance`
     * is the write behind any part of `$shape` that names none of its own.
     *
     * @return bool whether anything changed
     */
    public function addShape(Operand $operand, Shape $shape, ?Provenance $provenance = null): bool
    {
        if ($shape->isEmpty()) {
            return false;
        }

        if ($this->lastJoined->contains($operand) && $this->lastJoined[$operand] === $shape) {
            return false;
        }

        $this->lastJoined[$operand] = $shape;

        if ($provenance !== null) {
            $shape = $shape->bounded()->withProvenance($provenance);
        }

        $existing = $this->shapeOf($operand);
        $merged = $existing->joinBounded($shape);

        // A join that adds nothing hands back the shape it was given, and one
        // that adds anything makes a larger one.
        if ($merged === $existing) {
            return false;
        }

        $this->shapes[$operand] = $merged;

        return true;
    }

    /**
     * Copy every element under a literal key from one operand to another, each
     * with the write behind it, for `$b = $a`.
     *
     * @return bool whether anything changed
     */
    public function copyElements(Operand $from, Operand $to): bool
    {
        $changed = false;

        foreach ($this->shapeOf($from)->elements() as $key => $element) {
            if ($element->provenance() !== null) {
                $changed = $this->addShape($to, Shape::element($key, $element)) || $changed;
            }
        }

        return $changed;
    }

    /**
     * The write behind the element under `$key`, or behind the rest when
     * `$key` is null.
     */
    public function partProvenanceOf(Operand $operand, int|string|null $key): ?Provenance
    {
        $shape = $this->shapeOf($operand);

        return ($key === null ? $shape->restPart() : $shape->elementAt($key))->provenance();
    }

    /**
     * Everything this value carries, by any route.
     *
     * Its own taint and its whole shape, including the elements under literal
     * keys. Anywhere a value crosses a boundary that cannot carry keys — passed
     * to a function, reached by a sink, handed to an include — the precise
     * answer is unavailable and the whole of it has to travel.
     *
     * Leaving the per-key elements out of this was a false negative and a bad
     * one: `wpforms_panel_field( …, [ 'default' => $this->form->post_title ] )`
     * put the taint under one key, `effectiveTaintOf()` reported the array
     * clean, and the flow disappeared at the call. Findings went *down* on the
     * corpus, which is not the same as going right.
     *
     * Only a read that names a constant key may ask for less.
     */
    public function effectiveTaintOf(Operand $operand): TaintSet
    {
        return $this->taintOf($operand)->union($this->shapeOf($operand)->flatten());
    }

    /**
     * What one item of an array carries: its own taint, which every item
     * inherits, and what any element holds. Not what the keys carry, which
     * belongs to the keys alone: see {@see Shape::keysTaint()}.
     */
    public function itemsTaintOf(Operand $operand): TaintSet
    {
        $shape = $this->shapeOf($operand);

        return $this->taintOf($operand)
            ->union($shape->own())
            ->union($shape->elementsFlattened())
            ->union($shape->restPart()->flatten());
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

        if ($changed && $this->countsChanges) {
            $this->changeCounts[$operand] = ($this->changeCounts[$operand] ?? 0) + 1;
        }

        $this->taint[$operand] = $taint;

        if ($provenance !== null && ! $taint->isEmpty()) {
            $this->provenance[$operand] = $provenance;
        }

        return $changed;
    }

    /**
     * Turn on per-operand change counting, for the non-convergence invariant.
     *
     * Off by everywhere but a debug run, because it costs a hash write on every
     * taint change and answers a question a passing scan never asks: which
     * operand would not settle. An operand's value flips A->B->A only when two
     * ops write it disagreeing — this project's one recurring cause of a fixed
     * point that never converges, six times over — so the operand that changed
     * far more than the rest is the culprit, named without knowing the shape.
     */
    public function countChanges(): void
    {
        $this->countsChanges = true;
    }

    /**
     * Operands that changed value at least this many times, worst first.
     *
     * @return list<array{operand: Operand, changes: int}>
     */
    public function oscillators(int $threshold): array
    {
        $found = [];

        foreach ($this->changeCounts as $operand) {
            $count = $this->changeCounts[$operand];

            if ($count >= $threshold) {
                $found[] = ['operand' => $operand, 'changes' => $count];
            }
        }

        usort($found, static fn (array $a, array $b): int => $b['changes'] <=> $a['changes']);

        return $found;
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
