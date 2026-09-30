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
    /**
     * A variant a call asked for with literal keys alone: see
     * {@see FunctionSummary::variantKey()}.
     */
    public const LITERAL_VARIANT = 'literal';

    /**
     * A variant a method call on another object asked for: one bound to that
     * receiver, or the literal variant the call applies there. Each kind has
     * its own cap: see {@see InterproceduralResolver}.
     */
    public const RECEIVER_VARIANT = 'receiver';

    /** @var array<string, FunctionSummary> */
    private array $summaries = [];

    private ?ReadLog $log = null;

    /**
     * Variants a call asked for that the table does not hold yet: see
     * {@see FunctionSummary::variantKey()}. The next round analyses them.
     *
     * @var array<string, array{string, array<int, int|string>, string}> variant key => function key,
     *      bindings and kind
     */
    private array $requests = [];

    /**
     * Functions with every variant of a kind they may have: see
     * {@see markCapped()}.
     *
     * @var array<string, array<string, true>> function key => kinds
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
     * @param string                 $kind     {@see LITERAL_VARIANT} or {@see RECEIVER_VARIANT}
     */
    public function request(
        string $variantKey,
        string $functionKey,
        array $bindings,
        string $kind = self::LITERAL_VARIANT,
    ): void {
        $this->requests[strtolower($variantKey)] ??= [$functionKey, $bindings, $kind];
    }

    /**
     * @return array<string, array{string, array<int, int|string>, string}> variant key => function key,
     *         bindings and kind
     */
    public function requests(): array
    {
        return $this->requests;
    }

    /**
     * Record that a function has every variant of this kind it may have, so
     * a call asking for another applies a summary it already has. See
     * {@see FunctionAnalysis::variantOf()}.
     *
     * The two kinds are capped apart. One flag for both let 16 literal
     * variants stop every receiver variant, and 512 receiver variants stop
     * every literal one.
     */
    public function markCapped(string $functionKey, string $kind = self::LITERAL_VARIANT): void
    {
        $this->capped[strtolower($functionKey)][$kind] = true;
    }

    public function isCapped(string $functionKey, string $kind = self::LITERAL_VARIANT): bool
    {
        $this->log?->record('c:' . strtolower($functionKey));

        return isset($this->capped[strtolower($functionKey)][$kind]);
    }

    /**
     * @return array<string, array<string, true>> function key => kinds
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
