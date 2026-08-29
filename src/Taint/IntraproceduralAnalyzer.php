<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\IncludeGraph;
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
    public function __construct(
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
        private readonly CallResolver $resolver,
        private readonly AnalysisOptions $options,
        private readonly ?IncludeGraph $includes = null,
        /**
         * Used for one question: does anything in the scan call this function?
         * Null means the caller did not build a graph, and every function is
         * then treated as an entry point — the behaviour before there was one.
         */
        private readonly ?CallGraph $callGraph = null,
        /**
         * Function keys registered with `add_shortcode()`, whose parameters
         * carry post content.
         *
         * @var array<string, true>
         */
        private readonly array $shortcodeCallbacks = [],
        /**
         * Callbacks whose return value WordPress prints, and what each is.
         *
         * @var array<string, string>
         */
        private readonly array $printedReturns = [],
    ) {
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
        ScopeTable $scopes,
        ?int $seedParameterIndex = null,
        bool $collectFindings = true,
    ): AnalysisResult {
        // A probe run asks what one parameter reaches; it does not observe the
        // body as written, so nothing it writes belongs in the shared property
        // map. See PropertyTaintMap::$sealed.
        $properties = $seedParameterIndex === null ? $properties : $properties->sealed();

        return (new FunctionAnalysis(
            $context,
            $this->registry,
            $this->functions,
            $this->resolver,
            // Built per run: it consults the property map, which the caller
            // owns and which grows as the interprocedural rounds proceed.
            new LiteralAnalyzer($this->registry, $properties),
            $summaries,
            $properties,
            $scopes,
            $this->includes,
            new ReceiverResolver($this->functions->declaredTypes()),
            $this->options,
            $seedParameterIndex,
            $collectFindings,
            $this->callGraph,
            $this->shortcodeCallbacks,
            $this->printedReturns,
        ))->run();
    }
}
