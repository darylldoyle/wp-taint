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

    private ?ReadLog $log = null;

    /**
     * Variants a call asked for that the table does not hold yet: see
     * {@see FunctionSummary::variantKey()}. The next round analyses them.
     *
     * @var array<string, array{string, array<int, int|string>}> variant key => function key and bindings
     */
    private array $requests = [];

    /**
     * Functions with every summary for a fixed key they may have: see
     * {@see markCapped()}.
     *
     * @var array<string, true>
     */
    private array $capped = [];

    /**
     * Record every lookup from now on. See {@see ReadLog}.
     */
    public function recordReadsInto(?ReadLog $log): void
    {
        $this->log = $log;
    }

    public function get(string $key): ?FunctionSummary
    {
        $this->log?->record('s:' . strtolower($key));

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

    /**
     * Ask for a variant of a function's summary, for the next round.
     *
     * @param array<int, int|string> $bindings parameter index => literal
     */
    public function request(string $variantKey, string $functionKey, array $bindings): void
    {
        $this->requests[strtolower($variantKey)] ??= [$functionKey, $bindings];
    }

    /**
     * @return array<string, array{string, array<int, int|string>}> variant key => function key and bindings
     */
    public function requests(): array
    {
        return $this->requests;
    }

    /**
     * Record that a function has every summary for a fixed key it may have,
     * so a call asking for another applies the function's own summary in
     * full. See {@see FunctionAnalysis::variantOf()}.
     */
    public function markCapped(string $functionKey): void
    {
        $this->capped[strtolower($functionKey)] = true;
    }

    public function isCapped(string $functionKey): bool
    {
        $this->log?->record('c:' . strtolower($functionKey));

        return isset($this->capped[strtolower($functionKey)]);
    }

    /**
     * @return array<string, true>
     */
    public function capped(): array
    {
        return $this->capped;
    }

    public function has(string $key): bool
    {
        $this->log?->record('s:' . strtolower($key));

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
