<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Computes a function's {@see FunctionSummary}.
 *
 * The trick is one analysis run per parameter, each seeding only that
 * parameter with every taint kind. Whatever survives to the return value is
 * what that parameter contributes; whatever it does not is what the function
 * clears; and whichever sinks it reaches are the sinks a caller needs to know
 * about.
 *
 * Running the body once per parameter rather than once with a combined lattice
 * value keeps the analysis exact about *which* parameter reached what, at a cost
 * of N small runs over a body that is usually a few dozen ops. Functions with an
 * unusually long parameter list are capped and marked imprecise rather than
 * analysed at length.
 */
final class SummaryExtractor
{
    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly AnalysisOptions $options,
    ) {
    }

    public function extract(
        FunctionContext $context,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
    ): FunctionSummary {
        $parameterCount = $context->parameterCount();
        $analysed = min($parameterCount, $this->options->maxSummarisedParameters);

        $paramToReturn = [];
        $paramToSink = [];
        $clears = [];
        $paramToParam = [];
        $imprecise = $parameterCount > $analysed;

        for ($index = 0; $index < $analysed; $index++) {
            $result = $this->analyzer->analyze($context, $summaries, $properties, $index, false);

            $paramToReturn[$index] = $result->returnTaint;
            $clears[$index] = TaintSet::allDataflowKinds()->without($result->returnTaint);
            $paramToSink[$index] = self::deduplicate($result->sinksReached);
            $imprecise = $imprecise || $result->imprecise;

            // Where this parameter's taint ends up in the function's
            // out-parameters, which is the other half of what a caller needs:
            // `function fill( $in, array &$out )` moves taint sideways rather
            // than returning it.
            if ($result->byRefTaint !== []) {
                $paramToParam[$index] = $result->byRefTaint;
            }
        }

        // What the function returns with no parameter tainted at all: a wrapper
        // around get_option() introduces stored taint regardless of its
        // arguments, and a caller has to know that.
        $baseline = $this->analyzer->analyze($context, $summaries, $properties, null, false);

        return new FunctionSummary(
            $context->key,
            $context->displayName,
            $paramToReturn,
            $paramToSink,
            $clears,
            $baseline->returnTaint,
            $imprecise || $baseline->imprecise,
            $paramToParam,
            // The baseline run seeds nothing, so whatever reached an
            // out-parameter came from inside the body — a helper that fills its
            // argument straight from `$_GET`.
            $baseline->byRefTaint,
        );
    }

    /**
     * @param list<SinkReference> $references
     *
     * @return list<SinkReference>
     */
    private static function deduplicate(array $references): array
    {
        $unique = [];

        foreach ($references as $reference) {
            $unique[$reference->identityKey()] ??= $reference;
        }

        $result = array_values($unique);
        usort($result, static fn (SinkReference $a, SinkReference $b): int => $a->identityKey() <=> $b->identityKey());

        return $result;
    }
}
