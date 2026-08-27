<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Scan\WorkerPool;

/**
 * Drives summaries to a fixed point, then hands them to the finding pass.
 *
 * Summaries start at the bottom of the lattice — every function assumed to
 * propagate nothing — and are recomputed until nothing changes. That is what
 * makes recursion terminate: a recursive call reads the previous round's
 * summary rather than descending forever.
 *
 * The property taint map converges in the same loop, because
 * `$this->value = $_GET['x']` in one method and `echo $this->value` in another
 * is a single flow the per-function analysis cannot see on its own.
 *
 * ## Why each round reads a frozen table
 *
 * Every function in a round is summarised against the *previous* round's
 * summaries, not against summaries other functions produced earlier in the same
 * round. Reading them as they land would converge in fewer rounds, but it makes
 * the result depend on the order functions are visited — and the moment the
 * round is sharded across worker processes, that order is whatever the
 * scheduler picked.
 *
 * The transfer functions are monotone, so both orders reach the same least
 * fixed point. Freezing the table costs a round or two and buys a guarantee
 * that `--jobs=8` and `--jobs=1` produce byte-identical output.
 */
final class InterproceduralResolver
{
    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly SummaryExtractor $extractor,
        private readonly AnalysisOptions $options,
        private readonly int $jobs = 1,
    ) {
    }

    /**
     * @param list<FunctionContext> $functions
     *
     * @return array{summaries: SummaryTable, properties: PropertyTaintMap, rounds: int, converged: bool}
     */
    public function resolve(array $functions): array
    {
        $summaries = new SummaryTable();
        $properties = new PropertyTaintMap();

        if (! $this->options->interprocedural) {
            return ['summaries' => $summaries, 'properties' => $properties, 'rounds' => 0, 'converged' => true];
        }

        $ordered = self::callOrder($functions);
        $pool = new WorkerPool($this->jobs);
        $rounds = 0;
        $changed = true;

        while ($changed && $rounds < $this->options->maxInterproceduralRounds) {
            $rounds++;

            // The frozen inputs for this round. Workers read these and never
            // write them, so no worker can observe another's output.
            $previousSummaries = $summaries;
            $previousProperties = $properties;

            /** @var list<array{summaries: list<FunctionSummary>, properties: PropertyTaintMap}> $shards */
            $shards = $pool->run(
                fn (int $shard, int $shardCount): array => $this->round(
                    $ordered,
                    $previousSummaries,
                    $previousProperties,
                    $shard,
                    $shardCount,
                ),
            );

            $summaries = new SummaryTable();
            $properties = clone $previousProperties;
            $changed = false;

            // Merged in shard order, then in the order each shard produced
            // them. Both are fixed, so the merge is deterministic.
            foreach ($shards as $shardResult) {
                foreach ($shardResult['summaries'] as $summary) {
                    $summaries->set($summary);
                }

                $changed = $properties->mergeFrom($shardResult['properties']) || $changed;
            }

            foreach ($ordered as $context) {
                $previous = $previousSummaries->get($context->key);
                $current = $summaries->get($context->key);

                if ($previous === null || $current === null || ! $previous->equals($current)) {
                    $changed = true;
                }
            }
        }

        return [
            'summaries' => $summaries,
            'properties' => $properties,
            'rounds' => $rounds,
            'converged' => ! $changed,
        ];
    }

    /**
     * One round over one shard of the function list.
     *
     * @param list<FunctionContext> $ordered
     *
     * @return array{summaries: list<FunctionSummary>, properties: PropertyTaintMap}
     */
    private function round(
        array $ordered,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        int $shard,
        int $shardCount,
    ): array {
        // A private copy, so a worker's property writes stay in that worker
        // until the parent merges them.
        $roundProperties = clone $properties;
        $produced = [];

        foreach ($ordered as $index => $context) {
            if ($index % $shardCount !== $shard) {
                continue;
            }

            $produced[] = $this->extractor->extract($context, $summaries, $roundProperties);

            // A pass with no parameter seeded, purely so property writes in the
            // body land in the map. Findings are discarded.
            $this->analyzer->analyze($context, $summaries, $roundProperties, null, false);
        }

        return ['summaries' => $produced, 'properties' => $roundProperties];
    }

    /**
     * Callees before callers, approximately.
     *
     * A true reverse topological sort is impossible in the presence of
     * recursion and dynamic dispatch, and unnecessary: the fixed point
     * converges from any order. Ordering leaves first simply gets there in
     * fewer rounds. Sorting by key keeps it deterministic, which the round
     * sharding depends on.
     *
     * @param list<FunctionContext> $functions
     *
     * @return list<FunctionContext>
     */
    private static function callOrder(array $functions): array
    {
        $ordered = $functions;

        usort($ordered, static function (FunctionContext $a, FunctionContext $b): int {
            // `{main}` bodies call into everything else, so they go last.
            $mainOrder = ($a->isMain() ? 1 : 0) <=> ($b->isMain() ? 1 : 0);

            if ($mainOrder !== 0) {
                return $mainOrder;
            }

            return $a->key <=> $b->key;
        });

        return $ordered;
    }
}
