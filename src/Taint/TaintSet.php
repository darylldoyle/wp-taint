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
 */
final class TaintSet
{
    private const ALL_DATAFLOW_MASK = 0b0000_0111_1111_1111;

    private function __construct(private readonly int $mask)
    {
    }

    public static function empty(): self
    {
        return new self(0);
    }

    /**
     * Every kind the dataflow engine propagates. Excludes {@see TaintKind::Authz}.
     */
    public static function allDataflowKinds(): self
    {
        return new self(self::ALL_DATAFLOW_MASK);
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
        return new self($this->mask | $other->mask);
    }

    public function intersect(self $other): self
    {
        return new self($this->mask & $other->mask);
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
        return new self($this->mask & ~$other->mask);
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

    public function equals(self $other): bool
    {
        return $this->mask === $other->mask;
    }

    public function isSubsetOf(self $other): bool
    {
        return ($this->mask & ~$other->mask) === 0;
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
