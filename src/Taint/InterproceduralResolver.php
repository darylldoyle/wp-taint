<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Drives summaries to a fixed point, then analyses every function body with
 * those summaries in place.
 *
 * Summaries start at the bottom of the lattice — every function assumed to
 * propagate nothing — and are recomputed until nothing changes. That is what
 * makes recursion terminate: a recursive call reads the previous round's
 * summary rather than descending forever.
 *
 * The property taint map converges in the same loop, because
 * `$this->value = $_GET['x']` in one method and `echo $this->value` in another
 * is a single flow the per-function analysis cannot see on its own.
 */
final class InterproceduralResolver
{
    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly SummaryExtractor $extractor,
        private readonly AnalysisOptions $options,
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
        $rounds = 0;
        $changed = true;

        while ($changed && $rounds < $this->options->maxInterproceduralRounds) {
            $changed = false;
            $rounds++;

            foreach ($ordered as $context) {
                $summary = $this->extractor->extract($context, $summaries, $properties);
                $changed = $summaries->set($summary) || $changed;
            }

            // A round of plain body analysis, purely to let property writes
            // settle. Findings are discarded; only the property map matters.
            foreach ($ordered as $context) {
                $this->analyzer->analyze($context, $summaries, $properties, null, false);
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
     * Callees before callers, approximately.
     *
     * A true reverse topological sort is not possible in the presence of
     * recursion and dynamic dispatch, and is not needed: the fixed point
     * converges from any order. Ordering leaves first simply gets there in
     * fewer rounds. Sorting by key keeps it deterministic.
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
