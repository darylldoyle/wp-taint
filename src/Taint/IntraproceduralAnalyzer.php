<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Registry;

/**
 * Runs the propagation loop over a single function body.
 *
 * A thin factory: the loop itself lives in {@see FunctionAnalysis}, which holds
 * the mutable per-run state so that this class can stay stateless and be shared
 * across every function in a scan.
 */
final class IntraproceduralAnalyzer
{
    private readonly LiteralAnalyzer $literals;

    public function __construct(
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
        private readonly CallResolver $resolver,
        private readonly AnalysisOptions $options,
    ) {
        $this->literals = new LiteralAnalyzer($registry);
    }

    /**
     * @param int|null $seedParameterIndex when set, that parameter is seeded
     *                                     with every taint kind and no real
     *                                     sources are used — this is how
     *                                     summaries are extracted
     */
    public function analyze(
        FunctionContext $context,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ?int $seedParameterIndex = null,
        bool $collectFindings = true,
    ): AnalysisResult {
        return (new FunctionAnalysis(
            $context,
            $this->registry,
            $this->functions,
            $this->resolver,
            $this->literals,
            $summaries,
            $properties,
            $this->options,
            $seedParameterIndex,
            $collectFindings,
        ))->run();
    }
}
