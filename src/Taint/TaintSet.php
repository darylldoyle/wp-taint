<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use InvalidArgumentException;

/**
 * An immutable set of {@see TaintKind}, backed by an integer bitmask.
 *
 * The fixed point compares sets on every iteration of every block of every
 * function, so equality has to be a single integer comparison rather than an
 * array walk.
 *
 * A set can also say which parts of a parameter each kind came from. A probe
 * run that summarises a function seeds each part a parameter is read through
 * under its own number, such as `$field['desc']` and `$field['value']`, and a
 * caller then hands each part of its argument only what that part reached. A
 * kind with no parts named came from every part: a set built from kinds alone,
 * a source, or an operation that did not keep them. So a lost attribution
 * costs precision and never a finding. Outside a probe run no set names parts,
 * and every operation takes the plain path.
 */
final class TaintSet
{
    /** Every part of a parameter, as a part mask. */
    public const EVERY_PART = -1;

    /** How many parts a parameter can be split into: one bit each. */
    public const MAX_PARTS = 62;

    /**
     * @param array<int, int>|null $parts per kind bit, the parts it came from.
     *                                    A kind with no entry came from every
     *                                    part. Null when no kind names parts.
     */
    private function __construct(private readonly int $mask, private readonly ?array $parts = null)
    {
    }

    public static function empty(): self
    {
        return new self(0);
    }

    /**
     * Every kind the dataflow engine propagates. Excludes {@see TaintKind::Authz}.
     *
     * Derived from the enum rather than written out as a literal mask. It was a
     * literal, and adding a kind left it silently one bit short — every value
     * seeded as "all kinds" quietly lost the new one. A constant that has to be
     * kept in step with an enum by hand will eventually not be.
     *
     * Derived once per process. Every summary a call applies asks for it, and
     * building it filtered every case of the enum each time.
     */
    public static function allDataflowKinds(): self
    {
        /** @var self|null $all */
        static $all = null;

        return $all ??= self::of(...TaintKind::dataflowKinds());
    }

    public static function of(TaintKind ...$kinds): self
    {
        $mask = 0;

        foreach ($kinds as $kind) {
            $mask |= $kind->bit();
        }

        return new self($mask);
    }

    /**
     * @param list<string> $values
     */
    public static function fromStrings(array $values): self
    {
        $kinds = [];

        foreach ($values as $value) {
            $kind = TaintKind::tryFrom($value);

            if ($kind === null) {
                throw new InvalidArgumentException(sprintf('Unknown taint kind "%s".', $value));
            }

            $kinds[] = $kind;
        }

        return self::of(...$kinds);
    }

    public function union(self $other): self
    {
        $mask = $this->mask | $other->mask;

        if ($this->parts === null && $other->parts === null) {
            return new self($mask);
        }

        // Per kind, the parts either side has it from.
        $parts = [];

        for ($bits = $mask; $bits !== 0; $bits &= $bits - 1) {
            $bit = $bits & -$bits;
            $from = $this->partsOfBit($bit) | $other->partsOfBit($bit);

            if ($from !== self::EVERY_PART) {
                $parts[$bit] = $from;
            }
        }

        return new self($mask, $parts === [] ? null : $parts);
    }

    /**
     * The kinds of this set that `$other` also holds, from the parts this set
     * has them from. `$other` is a filter: the question is always which of a
     * value's kinds survive a check, a callee or a sink.
     */
    public function intersect(self $other): self
    {
        return $this->keeping($this->mask & $other->mask);
    }

    public function with(TaintKind ...$kinds): self
    {
        return $this->union(self::of(...$kinds));
    }

    public function clear(TaintKind ...$kinds): self
    {
        return $this->without(self::of(...$kinds));
    }

    public function without(self $other): self
    {
        return $this->keeping($this->mask & ~$other->mask);
    }

    public function clearAll(): self
    {
        return self::empty();
    }

    public function has(TaintKind $kind): bool
    {
        return ($this->mask & $kind->bit()) !== 0;
    }

    public function hasAny(self $other): bool
    {
        return ($this->mask & $other->mask) !== 0;
    }

    public function isEmpty(): bool
    {
        return $this->mask === 0;
    }

    /**
     * The same kinds, from the same parts.
     */
    public function equals(self $other): bool
    {
        // Every construction lists the kinds in ascending bit order, so two
        // sets with the same kinds from the same parts hold identical maps.
        return $this->mask === $other->mask && $this->parts === $other->parts;
    }

    /**
     * Whether every kind of this set is also in `$other`, whatever parts
     * either has it from.
     */
    public function isSubsetOf(self $other): bool
    {
        return ($this->mask & ~$other->mask) === 0;
    }

    /**
     * Whether `$other` already holds all of this set, each kind from at least
     * the parts this set has it from. A join that adds nothing by this test
     * adds nothing at all.
     */
    public function isCoveredBy(self $other): bool
    {
        if (($this->mask & ~$other->mask) !== 0) {
            return false;
        }

        if ($this->parts === null && $other->parts === null) {
            return true;
        }

        for ($bits = $this->mask; $bits !== 0; $bits &= $bits - 1) {
            $bit = $bits & -$bits;
            $mine = $this->partsOfBit($bit);

            if (($mine & ~$other->partsOfBit($bit)) !== 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * The same kinds, each from the one part numbered `$part`: a probe's seed.
     */
    public function fromPart(int $part): self
    {
        if ($part < 0 || $part >= self::MAX_PARTS) {
            throw new InvalidArgumentException(sprintf('Part %d is out of range.', $part));
        }

        $parts = [];

        for ($bits = $this->mask; $bits !== 0; $bits &= $bits - 1) {
            $parts[$bits & -$bits] = 1 << $part;
        }

        return new self($this->mask, $parts === [] ? null : $parts);
    }

    /**
     * The kinds that part `$part` brought, as a set that names no parts.
     */
    public function forPart(int $part): self
    {
        if ($this->parts === null) {
            return new self($this->mask);
        }

        $mask = 0;

        for ($bits = $this->mask; $bits !== 0; $bits &= $bits - 1) {
            $bit = $bits & -$bits;

            if (($this->partsOfBit($bit) & (1 << $part)) !== 0) {
                $mask |= $bit;
            }
        }

        return new self($mask);
    }

    /**
     * The parts `$kind` came from: {@see EVERY_PART} when it names none, and
     * 0 when the set does not hold it.
     */
    public function partsOf(TaintKind $kind): int
    {
        return $this->partsOfBit($kind->bit());
    }

    /**
     * Every part any kind of this set came from: 0 for an empty set.
     */
    public function parts(): int
    {
        if ($this->mask === 0) {
            return 0;
        }

        if ($this->parts === null || count($this->parts) < self::bitCount($this->mask)) {
            return self::EVERY_PART;
        }

        return array_reduce($this->parts, static fn (int $all, int $from): int => $all | $from, 0);
    }

    /**
     * Whether any kind names the parts it came from.
     */
    public function namesParts(): bool
    {
        return $this->parts !== null;
    }

    /**
     * The same kinds, named as coming from every part.
     */
    public function withoutParts(): self
    {
        return $this->parts === null ? $this : new self($this->mask);
    }

    private static function bitCount(int $mask): int
    {
        $count = 0;

        for ($bits = $mask; $bits !== 0; $bits &= $bits - 1) {
            $count++;
        }

        return $count;
    }

    private function partsOfBit(int $bit): int
    {
        if (($this->mask & $bit) === 0) {
            return 0;
        }

        return $this->parts[$bit] ?? self::EVERY_PART;
    }

    /**
     * The kinds in `$mask`, from the parts this set has them from.
     */
    private function keeping(int $mask): self
    {
        if ($this->parts === null) {
            return new self($mask);
        }

        $parts = [];

        foreach ($this->parts as $bit => $from) {
            if (($mask & $bit) !== 0) {
                $parts[$bit] = $from;
            }
        }

        return new self($mask, $parts === [] ? null : $parts);
    }

    public function count(): int
    {
        return count($this->kinds());
    }

    /**
     * Kinds in declaration order, so every rendering of a set is identical.
     *
     * @return list<TaintKind>
     */
    public function kinds(): array
    {
        return array_values(array_filter(
            TaintKind::cases(),
            fn (TaintKind $kind): bool => $this->has($kind),
        ));
    }

    /**
     * @return list<string>
     */
    public function toStrings(): array
    {
        return array_map(static fn (TaintKind $kind): string => $kind->value, $this->kinds());
    }

    public function describe(): string
    {
        if ($this->isEmpty()) {
            return '(none)';
        }

        return implode(', ', $this->toStrings());
    }
}
