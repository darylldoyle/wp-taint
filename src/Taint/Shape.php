<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * What an array holds, part by part.
 *
 * A value's own taint lives in {@see TaintState}'s own slot, which the op that
 * defines the value sets afresh on every pass. Its shape is what was written
 * into it through its elements, and a shape only ever grows. SSA gives an
 * array no new version on an element write, so the write and the definition
 * land on one operand, and a slot that both of them set is a slot they fight
 * over until the fixed point gives up.
 *
 * A shape has four parts:
 *
 * - elements: a shape per literal key, so `$a['title']` reads only what
 *   `'title'` was given
 * - rest: one shape for everything written under a computed key or appended
 *   with `[]`, which a read under any key has to see
 * - keys: the taint of keys written under a computed key
 * - own: for an element, that element's own taint, which everything under it
 *   inherits. The top of an operand's shape keeps it empty, because the
 *   operand's own taint is kept apart.
 *
 * Each part keeps the write behind its own taint, so a trace through an
 * element reaches the write that put the taint there, and a part copied out
 * of one array into another takes its trace with it.
 *
 * Shapes are immutable, so operands that copy one share it. They keep
 * {@see DEPTH} levels of elements below the value. A part deeper than that
 * folds into its node's own taint, which loses precision and never loses
 * taint.
 */
final class Shape
{
    /**
     * How many levels of elements a value keeps below itself.
     *
     * One level is what the per-key slots it replaces kept: an element holds
     * a flat set, so `$a['x']['y']` reads everything under `'x'`.
     */
    public const DEPTH = 1;

    private static ?self $empty = null;

    private ?TaintSet $flat = null;

    /**
     * @param array<array-key, self> $elements none of them empty
     */
    private function __construct(
        private readonly TaintSet $own,
        private readonly TaintSet $keys,
        private readonly array $elements,
        private readonly ?self $rest,
        private readonly ?Provenance $provenance = null,
        private readonly ?Provenance $keysProvenance = null,
    ) {
    }

    public static function empty(): self
    {
        return self::$empty ??= new self(TaintSet::empty(), TaintSet::empty(), [], null);
    }

    /**
     * A value with no parts of its own: a scalar, or an array known only as a
     * whole.
     */
    public static function of(TaintSet $own, ?Provenance $provenance = null): self
    {
        return $own->isEmpty() ? self::empty() : new self($own, TaintSet::empty(), [], null, $provenance);
    }

    /**
     * An array whose keys carry `$keys`: what a write under a computed key
     * used as the key.
     */
    public static function keys(TaintSet $keys, ?Provenance $provenance = null): self
    {
        return $keys->isEmpty()
            ? self::empty()
            : new self(TaintSet::empty(), $keys, [], null, null, $provenance);
    }

    /**
     * An array whose only part is `$value` under a literal key.
     */
    public static function element(int|string $key, self $value): self
    {
        $value = $value->cut(self::DEPTH - 1);

        return $value->isEmpty()
            ? self::empty()
            : new self(TaintSet::empty(), TaintSet::empty(), [$key => $value], null);
    }

    /**
     * An array whose only part is `$value` under a computed key.
     */
    public static function rest(self $value): self
    {
        $value = $value->cut(self::DEPTH - 1);

        return $value->isEmpty() ? self::empty() : new self(TaintSet::empty(), TaintSet::empty(), [], $value);
    }

    public function own(): TaintSet
    {
        return $this->own;
    }

    public function keysTaint(): TaintSet
    {
        return $this->keys;
    }

    /**
     * The write that made a key carry its taint.
     */
    public function keysProvenance(): ?Provenance
    {
        return $this->keysProvenance;
    }

    /**
     * The write behind this part's own taint.
     */
    public function provenance(): ?Provenance
    {
        return $this->provenance;
    }

    /**
     * This shape with `$provenance` as the write behind every part that
     * carries taint and names no write of its own.
     */
    public function withProvenance(Provenance $provenance): self
    {
        if ($this->isEmpty()) {
            return $this;
        }

        $elements = [];

        foreach ($this->elements as $key => $element) {
            $elements[$key] = $element->withProvenance($provenance);
        }

        return new self(
            $this->own,
            $this->keys,
            $elements,
            $this->rest?->withProvenance($provenance),
            $this->provenance ?? ($this->own->isEmpty() ? null : $provenance),
            $this->keysProvenance ?? ($this->keys->isEmpty() ? null : $provenance),
        );
    }

    /**
     * @return array<array-key, self>
     */
    public function elements(): array
    {
        return $this->elements;
    }

    public function elementAt(int|string $key): self
    {
        return $this->elements[$key] ?? self::empty();
    }

    public function restPart(): self
    {
        return $this->rest ?? self::empty();
    }

    public function isEmpty(): bool
    {
        return $this->own->isEmpty()
            && $this->keys->isEmpty()
            && $this->elements === []
            && $this->rest === null;
    }

    /**
     * Everything this shape holds, by any route.
     *
     * What a sink, a string context or a call that cannot carry keys sees.
     */
    public function flatten(): TaintSet
    {
        if ($this->flat !== null) {
            return $this->flat;
        }

        $set = $this->own->union($this->keys);

        foreach ($this->elements as $element) {
            $set = $set->union($element->flatten());
        }

        if ($this->rest !== null) {
            $set = $set->union($this->rest->flatten());
        }

        return $this->flat = $set;
    }

    /**
     * Union of every element under a literal key, each flattened.
     */
    public function elementsFlattened(): TaintSet
    {
        $set = TaintSet::empty();

        foreach ($this->elements as $element) {
            $set = $set->union($element->flatten());
        }

        return $set;
    }

    /**
     * Each element under a literal key, flattened, for handing an array
     * across a boundary that keeps keys but not their structure.
     *
     * @return array<array-key, TaintSet>
     */
    public function elementsFlattenedByKey(): array
    {
        return array_map(static fn (self $element): TaintSet => $element->flatten(), $this->elements);
    }

    public function join(self $other): self
    {
        if ($other === $this || $other->isEmpty()) {
            return $this;
        }

        if ($this->isEmpty()) {
            return $other;
        }

        // Most joins add nothing: every pass writes the same elements again.
        // Handing back this shape unchanged lets the caller see that without
        // comparing the two, and keeps the write behind each part as it was.
        if ($other->isWithin($this)) {
            return $this;
        }

        $elements = $this->elements;

        foreach ($other->elements as $key => $element) {
            $elements[$key] = isset($elements[$key]) ? $elements[$key]->join($element) : $element;
        }

        $rest = match (true) {
            $this->rest === null => $other->rest,
            $other->rest === null => $this->rest,
            default => $this->rest->join($other->rest),
        };

        // A part keeps the write behind it until another write adds to its
        // taint. The trace then follows the newer write, as the per-key slots
        // did.
        $provenance = $other->own->isSubsetOf($this->own)
            ? $this->provenance ?? $other->provenance
            : $other->provenance ?? $this->provenance;

        $keysProvenance = $other->keys->isSubsetOf($this->keys)
            ? $this->keysProvenance ?? $other->keysProvenance
            : $other->keysProvenance ?? $this->keysProvenance;

        return new self(
            $this->own->union($other->own),
            $this->keys->union($other->keys),
            $elements,
            $rest,
            $provenance,
            $keysProvenance,
        );
    }

    public function equals(self $other): bool
    {
        if ($other === $this) {
            return true;
        }

        if (
            ! $this->own->equals($other->own)
            || ! $this->keys->equals($other->keys)
            || count($this->elements) !== count($other->elements)
            || ($this->rest === null) !== ($other->rest === null)
        ) {
            return false;
        }

        foreach ($this->elements as $key => $element) {
            if (! isset($other->elements[$key]) || ! $element->equals($other->elements[$key])) {
                return false;
            }
        }

        return $this->rest === null || $other->rest === null || $this->rest->equals($other->rest);
    }

    /**
     * Whether every part of this shape, and all its taint, is already in
     * `$other`.
     */
    private function isWithin(self $other): bool
    {
        if (! $this->own->isSubsetOf($other->own) || ! $this->keys->isSubsetOf($other->keys)) {
            return false;
        }

        foreach ($this->elements as $key => $element) {
            if (! isset($other->elements[$key]) || ! $element->isWithin($other->elements[$key])) {
                return false;
            }
        }

        return $this->rest === null || ($other->rest !== null && $this->rest->isWithin($other->rest));
    }

    /**
     * This shape with `$levels` levels of elements kept below it. Anything
     * deeper folds into the node at the last level kept.
     */
    public function cut(int $levels): self
    {
        if ($this->elements === [] && $this->rest === null) {
            return $this;
        }

        if ($levels <= 0) {
            return self::of($this->flatten(), $this->provenance ?? $this->firstProvenance());
        }

        $elements = [];

        foreach ($this->elements as $key => $element) {
            $elements[$key] = $element->cut($levels - 1);
        }

        return new self(
            $this->own,
            $this->keys,
            $elements,
            $this->rest?->cut($levels - 1),
            $this->provenance,
            $this->keysProvenance,
        );
    }

    /**
     * The write behind the first part below this one that names one, for a
     * part folded into its node.
     */
    private function firstProvenance(): ?Provenance
    {
        foreach ($this->elements as $element) {
            $provenance = $element->provenance ?? $element->firstProvenance();

            if ($provenance !== null) {
                return $provenance;
            }
        }

        return $this->rest === null ? null : $this->rest->provenance ?? $this->rest->firstProvenance();
    }
}
