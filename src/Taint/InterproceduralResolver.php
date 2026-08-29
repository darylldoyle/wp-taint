<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Scan\NullScanProgress;
use Enshrined\WpTaint\Scan\ScanProgress;
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
 * is a single flow the per-function analysis cannot see on its own. So does the
 * scope table, for the same reason one step further out: an included template
 * sees the includer's variables, and the includer sees whatever the template
 * left behind.
 *
 * ## What each round is allowed to see
 *
 * A worker reads the previous round's summaries plus **its own** results from
 * the current round. It never sees another worker's, because that would make
 * the answer depend on the order the scheduler happened to run them in.
 *
 * Reading its own results back is what keeps the round count down. Freezing the
 * table completely was correct but slow: it pushed real plugins from five or
 * six rounds to nine or ten, and eleven of the corpus fifty straight past the
 * cap into silently incomplete summaries.
 *
 * Determinism survives because the transfer functions are monotone, so every
 * schedule reaches the same least fixed point, and because the merge is in
 * shard order rather than completion order. With `--jobs=1` there is one shard,
 * so this is plain in-place iteration.
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
     * @return array{summaries: SummaryTable, properties: PropertyTaintMap, scopes: ScopeTable, rounds: int,
     *     converged: bool}
     */
    public function resolve(array $functions, ScanProgress $progress = new NullScanProgress()): array
    {
        $summaries = new SummaryTable();
        $properties = new PropertyTaintMap();
        $scopes = new ScopeTable();

        if (! $this->options->interprocedural) {
            return [
                'summaries' => $summaries,
                'properties' => $properties,
                'scopes' => $scopes,
                'rounds' => 0,
                'converged' => true,
            ];
        }

        $ordered = self::callOrder($functions);
        $pool = new WorkerPool($this->jobs);
        $rounds = 0;
        $changed = true;

        // The fixed point cannot say how many rounds it needs until it stops
        // needing them, so the phase reports a round count rather than a
        // percentage. Real plugins settle in five to eight.
        $progress->phase('Resolving taint across functions', null);

        while ($changed && $rounds < $this->options->maxInterproceduralRounds) {
            $rounds++;
            $progress->advance();

            // This round's shared starting point. Each worker copies it and
            // adds only its own results, so no worker sees another's.
            $previousSummaries = $summaries;
            $previousProperties = $properties;
            $previousScopes = $scopes;

            /** @var list<array{summaries: list<FunctionSummary>, properties: PropertyTaintMap,
             *     scopes: ScopeTable}> $shards */
            $shards = $pool->run(
                fn (int $shard, int $shardCount): array => $this->round(
                    $ordered,
                    $previousSummaries,
                    $previousProperties,
                    $previousScopes,
                    $shard,
                    $shardCount,
                ),
            );

            $summaries = new SummaryTable();
            $properties = clone $previousProperties;
            $scopes = clone $previousScopes;
            $changed = false;

            // Merged in shard order, then in the order each shard produced
            // them. Both are fixed, so the merge is deterministic.
            foreach ($shards as $shardResult) {
                foreach ($shardResult['summaries'] as $summary) {
                    $summaries->put($summary);
                }

                $changed = $properties->mergeFrom($shardResult['properties']) || $changed;
                $changed = $scopes->mergeFrom($shardResult['scopes']) || $changed;
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
            'scopes' => $scopes,
            'rounds' => $rounds,
            'converged' => ! $changed,
        ];
    }

    /**
     * One round over one shard of the function list.
     *
     * @param list<FunctionContext> $ordered
     *
     * @return array{summaries: list<FunctionSummary>, properties: PropertyTaintMap, scopes: ScopeTable}
     */
    private function round(
        array $ordered,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
        int $shard,
        int $shardCount,
    ): array {
        // A private copy, so a worker's property writes stay in that worker
        // until the parent merges them.
        $roundProperties = clone $properties;
        $roundScopes = clone $scopes;
        $produced = [];

        // A private view: the previous round's summaries, plus whatever this
        // worker produces as it goes. Another worker's output never lands here.
        $visible = new SummaryTable();

        foreach ($summaries->all() as $summary) {
            $visible->put($summary);
        }

        foreach ($ordered as $index => $context) {
            if ($index % $shardCount !== $shard) {
                continue;
            }

            $summary = $this->extractor->extract($context, $visible, $roundProperties, $roundScopes);
            $visible->put($summary);
            $produced[] = $summary;

            // A pass with no parameter seeded, purely so property writes in the
            // body land in the map. Findings are discarded.
            $this->analyzer->analyze($context, $visible, $roundProperties, $roundScopes, null, false);
        }

        return ['summaries' => $produced, 'properties' => $roundProperties, 'scopes' => $roundScopes];
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
