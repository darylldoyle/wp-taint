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
 *
 * ## Which functions a round analyses
 *
 * After the first round, only the functions that read something the previous
 * round changed. A function's analysis reads nothing shared but the summary
 * table, the property map and the scope table, and every read is recorded as
 * it happens (see {@see ReadLog}), so a function none of whose reads moved
 * would produce exactly what it produced last time. Its previous summary
 * stands.
 *
 * Within a round, a summary that changes makes its readers later in the same
 * slice dirty at once, which is what they would have seen had every function
 * been re-analysed. Waiting for the next round moved a chain one level per
 * round. {@see AnalysisOptions::$incrementalRounds} turns this off, and
 * `tools/compare-incremental.php` checks the two agree exactly.
 */
final class InterproceduralResolver
{
    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly SummaryExtractor $extractor,
        private readonly AnalysisOptions $options,
        private readonly int $jobs = 1,
        /**
         * What calls what, for ordering callees before callers. Without it the
         * order falls back to sorting by key, which is correct but can cost a
         * round per level of a call chain.
         */
        private readonly ?CallGraph $callGraph = null,
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

        $ordered = self::callOrder($functions, $this->callGraph);
        $pool = new WorkerPool($this->jobs);
        $rounds = 0;
        $changed = true;

        // Which functions the next round analyses: null for all of them. The
        // first round has nothing to go on, and with incremental rounds off
        // every round is a first round.
        /** @var array<string, true>|null $dirty */
        $dirty = null;

        /** @var array<string, list<string>> $readsOf function key => entries its last analysis read */
        $readsOf = [];

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
            $roundDirty = $dirty;
            $readers = $this->options->incrementalRounds ? self::readersOf($readsOf) : [];

            /** @var list<array{summaries: list<FunctionSummary>, properties: PropertyTaintMap,
             *     scopes: ScopeTable, reads: array<string, list<string>>}> $shards */
            $shards = $pool->run(
                fn (int $shard, int $shardCount): array => $this->round(
                    $ordered,
                    $previousSummaries,
                    $previousProperties,
                    $previousScopes,
                    $shard,
                    $shardCount,
                    $roundDirty,
                    $readers,
                ),
            );

            // A function not analysed this round keeps last round's summary:
            // nothing it read has changed, so it would have produced the same.
            $summaries = new SummaryTable();

            foreach ($previousSummaries->all() as $summary) {
                $summaries->put($summary);
            }

            $properties = clone $previousProperties;
            $scopes = clone $previousScopes;
            $changed = false;

            /** @var array<string, true> $moved ReadLog entries that changed this round */
            $moved = [];

            // Merged in shard order, then in the order each shard produced
            // them. Both are fixed, so the merge is deterministic.
            foreach ($shards as $shardResult) {
                foreach ($shardResult['summaries'] as $summary) {
                    $previous = $previousSummaries->get($summary->key);

                    if ($previous === null || ! $previous->equals($summary)) {
                        $changed = true;
                        $moved['s:' . strtolower($summary->key)] = true;
                    }

                    $summaries->put($summary);
                }

                foreach ($properties->mergeChangedKeys($shardResult['properties']) as $key) {
                    $changed = true;
                    $moved['p:' . $key] = true;
                    $moved['p*:' . substr($key, (int) strpos($key, '::') + 2)] = true;
                }

                $scopeChanges = $scopes->mergeChanges($shardResult['scopes']);
                $changed = $scopeChanges['changed'] || $changed;

                foreach ($scopeChanges['entries'] as $entry) {
                    $moved[$entry] = true;
                }

                foreach ($shardResult['reads'] as $key => $entries) {
                    $readsOf[$key] = $entries;
                }
            }

            // Every function must have a summary once the first round is done.
            // Only a function never analysed could lack one, which the dirty
            // set below never allows; checked rather than assumed.
            foreach ($ordered as $context) {
                if ($summaries->get($context->key) === null) {
                    $changed = true;
                }
            }

            if (! $this->options->incrementalRounds) {
                continue;
            }

            $dirty = [];

            foreach ($readsOf as $key => $entries) {
                foreach ($entries as $entry) {
                    if (isset($moved[$entry])) {
                        $dirty[$key] = true;

                        break;
                    }
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
     * @param array<string, true>|null        $dirty   the functions to analyse, or null for all of them
     * @param array<string, list<string>>     $readers ReadLog entry => the functions that read it last time
     *
     * @return array{summaries: list<FunctionSummary>, properties: PropertyTaintMap, scopes: ScopeTable,
     *     reads: array<string, list<string>>}
     */
    private function round(
        array $ordered,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
        int $shard,
        int $shardCount,
        ?array $dirty = null,
        array $readers = [],
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

        // Every shared read, attributed to the function doing it. Probe runs
        // read through sealed copies of the property map, which share the log.
        $log = new ReadLog();
        $visible->recordReadsInto($log);
        $roundProperties->recordReadsInto($log);
        $roundScopes->recordReadsInto($log);

        // Grouped by key, so a function declared twice — a conditional shim, a
        // vendored copy — publishes one summary carrying the worst of both
        // bodies, rather than whichever copy happened to be analysed last.
        // First-occurrence order keeps the leaves-first ordering and the shard
        // split deterministic.
        $groups = [];

        foreach ($ordered as $context) {
            $groups[$context->key][] = $context;
        }

        // A contiguous slice of the callees-first order, not every Nth group.
        // A worker sees only its own results within a round, so striping put
        // each link of a call chain in a different worker and moved the chain
        // one level per round. A slice keeps a chain together, and one that
        // spans workers crosses at most $shardCount - 1 boundaries.
        $groupCount = count($groups);
        $first = intdiv($groupCount * $shard, $shardCount);
        $last = intdiv($groupCount * ($shard + 1), $shardCount);
        $index = -1;

        foreach ($groups as $group) {
            $index++;

            if ($index < $first || $index >= $last) {
                continue;
            }

            $key = $group[0]->key;

            // Sliced by position in the whole order, then filtered, so a
            // function stays with the same worker every round and a chain is
            // not scattered across workers by a small dirty set.
            if ($dirty !== null && ! isset($dirty[$key])) {
                continue;
            }

            $summary = null;
            $log->begin($key);

            foreach ($group as $context) {
                $extracted = $this->extractor->extract($context, $visible, $roundProperties, $roundScopes);
                $summary = $summary === null ? $extracted : $summary->union($extracted);
            }

            $visible->put($summary);
            $produced[] = $summary;

            // A changed summary makes its readers later in this slice dirty now,
            // not next round: re-analysing everything, they would have seen it
            // this round, and waiting moves a chain one level per round.
            if ($dirty !== null) {
                $previous = $summaries->get($key);

                if ($previous === null || ! $previous->equals($summary)) {
                    foreach ($readers['s:' . $key] ?? [] as $reader) {
                        $dirty[$reader] = true;
                    }
                }
            }

            foreach ($group as $context) {
                // A pass with no parameter seeded, purely so property writes in
                // the body land in the map. Findings are discarded.
                $this->analyzer->analyze($context, $visible, $roundProperties, $roundScopes, null, false);
            }
        }

        $log->reader = null;

        // The log is this worker's, and would otherwise travel back to the
        // parent inside every table it is attached to.
        $roundProperties->recordReadsInto(null);
        $roundScopes->recordReadsInto(null);

        return [
            'summaries' => $produced,
            'properties' => $roundProperties,
            'scopes' => $roundScopes,
            'reads' => $log->all(),
        ];
    }

    /**
     * @param array<string, list<string>> $readsOf function key => entries it read
     *
     * @return array<string, list<string>> entry => functions that read it
     */
    private static function readersOf(array $readsOf): array
    {
        $readers = [];

        foreach ($readsOf as $key => $entries) {
            foreach ($entries as $entry) {
                if (str_starts_with($entry, 's:')) {
                    $readers[$entry][] = $key;
                }
            }
        }

        return $readers;
    }

    /**
     * Callees before callers.
     *
     * A function's summary is only as good as its callees' summaries when it
     * is extracted, and each worker reads back its own results within a round.
     * So a callee summarised first is one its callers see straight away, and an
     * acyclic chain of any depth settles in a single round.
     *
     * Sorting by key alone was the old order. It converges too, but a chain
     * whose callers sort before their callees moved one level per round, and
     * the round cap turned that into a depth limit: 31 levels and no further.
     *
     * Recursion makes a strict order impossible, so functions that call each
     * other are grouped (Tarjan's strongly connected components) and the
     * groups are ordered callees first; the fixed point settles the rest.
     * Everything is visited in key order, so the result is deterministic, which
     * the round sharding depends on.
     *
     * @param list<FunctionContext> $functions
     *
     * @return list<FunctionContext>
     */
    private static function callOrder(array $functions, ?CallGraph $callGraph): array
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

        if ($callGraph === null) {
            return $ordered;
        }

        /** @var array<string, list<FunctionContext>> $byKey */
        $byKey = [];

        foreach ($ordered as $context) {
            $byKey[$context->key][] = $context;
        }

        $rank = array_flip(array_keys($byKey));
        $result = [];

        foreach (self::componentsCalleesFirst(array_keys($byKey), $callGraph) as $component) {
            usort($component, static fn (string $a, string $b): int => ($rank[$a] ?? 0) <=> ($rank[$b] ?? 0));

            foreach ($component as $key) {
                foreach ($byKey[$key] ?? [] as $context) {
                    $result[] = $context;
                }
            }
        }

        return $result;
    }

    /**
     * Tarjan's algorithm, iteratively: a deep call chain would otherwise be a
     * deep PHP stack. Components come out callees first, which is the order
     * Tarjan emits them in.
     *
     * @param list<string> $keys
     *
     * @return list<list<string>>
     */
    private static function componentsCalleesFirst(array $keys, CallGraph $callGraph): array
    {
        $known = array_flip($keys);
        $index = [];
        $low = [];
        $onStack = [];
        $stack = [];
        $components = [];
        $next = 0;

        foreach ($keys as $root) {
            if (isset($index[$root])) {
                continue;
            }

            /** @var list<array{0: string, 1: list<string>, 2: int}> $work key, callees, next callee position */
            $work = [[$root, self::knownCallees($root, $callGraph, $known), 0]];
            $index[$root] = $low[$root] = $next++;
            $stack[] = $root;
            $onStack[$root] = true;

            while ($work !== []) {
                $top = count($work) - 1;
                [$key, $callees, $position] = $work[$top];

                $callee = $callees[$position] ?? null;

                if ($callee !== null) {
                    $work[$top][2]++;

                    if (! isset($index[$callee])) {
                        $index[$callee] = $low[$callee] = $next++;
                        $stack[] = $callee;
                        $onStack[$callee] = true;
                        $work[] = [$callee, self::knownCallees($callee, $callGraph, $known), 0];
                    } elseif (isset($onStack[$callee])) {
                        $low[$key] = min($low[$key] ?? 0, $index[$callee]);
                    }

                    continue;
                }

                array_pop($work);

                if ($work !== []) {
                    $parent = $work[count($work) - 1][0];
                    $low[$parent] = min($low[$parent] ?? 0, $low[$key] ?? 0);
                }

                if (($low[$key] ?? null) !== ($index[$key] ?? null)) {
                    continue;
                }

                $component = [];

                do {
                    $member = array_pop($stack);

                    if ($member === null) {
                        break;
                    }

                    unset($onStack[$member]);
                    $component[] = $member;
                } while ($member !== $key);

                $components[] = $component;
            }
        }

        return $components;
    }

    /**
     * @param array<string, int> $known
     *
     * @return list<string>
     */
    private static function knownCallees(string $key, CallGraph $callGraph, array $known): array
    {
        $callees = array_values(array_unique(array_filter(
            $callGraph->calleesOf($key),
            static fn (string $callee): bool => isset($known[$callee]),
        )));
        sort($callees);

        return $callees;
    }
}
