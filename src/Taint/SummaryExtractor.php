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
    /**
     * Each function's parameter keys, which do not change between rounds.
     *
     * @var array<string, array<int, list<array-key>>>
     */
    private array $parameterKeys = [];

    /**
     * Each function's parameter parts, which do not change between rounds.
     *
     * @var array<string, array<int, list<list<int|string>>>>
     */
    private array $parameterParts = [];

    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly AnalysisOptions $options,
        private readonly ParameterKeyReads $keyReads,
    ) {
    }

    public function extract(
        FunctionContext $context,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
    ): FunctionSummary {
        $parameterCount = $context->parameterCount();
        $analysed = min($parameterCount, $this->options->maxSummarisedParameters);

        $paramToReturn = [];
        $paramToSink = [];
        $clears = [];
        $paramToParam = [];
        $paramToProperty = [];
        $paramToCapture = [];
        $paramToScope = [];
        $paramToReturnContainer = [];
        $paramToReturnKeyed = [];
        $paramToReturnKeys = [];
        $revertedResiduals = [];
        $imprecise = $parameterCount > $analysed;

        $parts = $this->parameterParts[$context->key] ??= ParameterParts::of($context->func);

        for ($index = 0; $index < $analysed; $index++) {
            $result = $this->analyzer->analyze(
                $context,
                $summaries,
                $properties,
                $scopes,
                $index,
                false,
                $parts[$index] ?? [],
            );

            $paramToReturn[$index] = $result->returnTaint;

            if ($result->revertedResiduals !== null && ! $result->revertedResiduals->isEmpty()) {
                $revertedResiduals[$index] = $result->revertedResiduals;
            }

            // And what it puts into the returned array's elements, which a
            // caller reads the way it reads a local array's.
            if ($result->returnContainer !== null && ! $result->returnContainer->isEmpty()) {
                $paramToReturnContainer[$index] = $result->returnContainer;
            }

            if ($result->returnKeyed !== []) {
                $keyed = $result->returnKeyed;
                ksort($keyed);
                $paramToReturnKeyed[$index] = $keyed;
            }

            if ($result->returnKeys !== null && ! $result->returnKeys->isEmpty()) {
                $paramToReturnKeys[$index] = $result->returnKeys;
            }
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

            // Where this parameter is written into a property. A probe run's
            // property map is sealed, so the write is recorded rather than
            // performed, and the call site applies what the caller passed.
            if ($result->propertiesReached !== []) {
                $paramToProperty[$index] = $result->propertiesReached;
            }

            // And where it is captured by a closure, for the same reason:
            // the probe run records, the call site publishes.
            if ($result->capturesReached !== []) {
                $paramToCapture[$index] = $result->capturesReached;
            }

            // And the scopes it reaches: files it includes, templates it
            // hands arguments to, closures that write it back. Same reason.
            if ($result->scopesReached !== []) {
                $paramToScope[$index] = $result->scopesReached;
            }
        }

        // What the function returns with no parameter tainted at all: a wrapper
        // around get_option() introduces stored taint regardless of its
        // arguments, and a caller has to know that.
        $baseline = $this->analyzer->analyze($context, $summaries, $properties, $scopes, null, false);

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
            // The baseline run, because whether a return carries a literal is a
            // property of the body and not of which parameter was seeded.
            $baseline->returnAnchored,
            $paramToProperty,
            $paramToCapture,
            $paramToScope,
            $paramToReturnContainer,
            $paramToReturnKeyed,
            $baseline->returnContainer,
            self::sorted($baseline->returnKeyed),
            $this->parameterKeys[$context->key] ??= $this->keyReads->of($context->func),
            $revertedResiduals,
            $paramToReturnKeys,
            $baseline->returnKeys,
            array_filter(
                $parts,
                static fn (int $index): bool => $index < $analysed,
                ARRAY_FILTER_USE_KEY,
            ),
        );
    }

    /**
     * @param array<array-key, TaintSet> $keyed
     *
     * @return array<array-key, TaintSet>
     */
    private static function sorted(array $keyed): array
    {
        ksort($keyed);

        return $keyed;
    }

    /**
     * @param list<SinkReference> $references
     *
     * @return list<SinkReference>
     */
    private static function deduplicate(array $references): array
    {
        $unique = [];

        // One sink reached through two parts is reached by both.
        foreach ($references as $reference) {
            $key = $reference->identityKey();
            $unique[$key] = isset($unique[$key])
                ? $unique[$key]->withParts($unique[$key]->parts | $reference->parts)
                : $reference;
        }

        $result = array_values($unique);
        usort($result, static fn (SinkReference $a, SinkReference $b): int => $a->identityKey() <=> $b->identityKey());

        return $result;
    }
}
