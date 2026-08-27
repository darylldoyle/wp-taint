<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Function summaries, keyed the same way {@see UserFunctionTable} is.
 *
 * Before the first round of the interprocedural fixed point every function is
 * assumed to do nothing: no taint reaches the return, no parameter reaches a
 * sink. That is the bottom of the lattice, and iterating from it upwards is
 * what makes recursion terminate.
 */
final class SummaryTable
{
    /** @var array<string, FunctionSummary> */
    private array $summaries = [];

    public function get(string $key): ?FunctionSummary
    {
        return $this->summaries[strtolower($key)] ?? null;
    }

    public function set(FunctionSummary $summary): bool
    {
        $key = strtolower($summary->key);
        $existing = $this->summaries[$key] ?? null;
        $this->summaries[$key] = $summary;

        return $existing === null || ! $existing->equals($summary);
    }

    public function has(string $key): bool
    {
        return isset($this->summaries[strtolower($key)]);
    }

    /**
     * @return array<string, FunctionSummary>
     */
    public function all(): array
    {
        return $this->summaries;
    }
}
