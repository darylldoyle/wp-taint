<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * Which arguments of a call an entry applies to.
 */
final class ArgumentSelector
{
    /**
     * @param list<int>|null $indexes null means every argument
     */
    private function __construct(private readonly ?array $indexes)
    {
    }

    public static function all(): self
    {
        return new self(null);
    }

    public static function index(int $index): self
    {
        return new self([$index]);
    }

    /**
     * @param list<int> $indexes
     */
    public static function indexes(array $indexes): self
    {
        sort($indexes);

        return new self($indexes);
    }

    public function matchesEverything(): bool
    {
        return $this->indexes === null;
    }

    public function contains(int $index): bool
    {
        return $this->indexes === null || in_array($index, $this->indexes, true);
    }

    /**
     * Concrete argument positions for a call with the given arity.
     *
     * @return list<int>
     */
    public function resolve(int $argumentCount): array
    {
        if ($this->indexes === null) {
            return range(0, max(0, $argumentCount - 1));
        }

        return array_values(array_filter($this->indexes, static fn (int $i): bool => $i < $argumentCount));
    }

    public function firstIndex(): int
    {
        return $this->indexes[0] ?? 0;
    }

    public function describe(): string
    {
        if ($this->indexes === null) {
            return '*';
        }

        return implode(',', $this->indexes);
    }
}
