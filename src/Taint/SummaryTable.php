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

    /**
     * Store a summary and report whether it differed from what was there.
     *
     * The comparison is structural and sorts sink lists, so it is not free.
     * Use {@see put()} where the answer is not wanted.
     */
    public function set(FunctionSummary $summary): bool
    {
        $key = strtolower($summary->key);
        $existing = $this->summaries[$key] ?? null;
        $this->summaries[$key] = $summary;

        return $existing === null || ! $existing->equals($summary);
    }

    /**
     * Store a summary without asking whether it changed.
     *
     * A worker building its own view of the table calls this once per function
     * per round; only the parent's merge needs change detection, and paying for
     * a structural comparison in the inner loop is measurable on a tree the
     * size of WooCommerce.
     */
    public function put(FunctionSummary $summary): void
    {
        $this->summaries[strtolower($summary->key)] = $summary;
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
