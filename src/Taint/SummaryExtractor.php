<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\ArgumentSelector;

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

    /**
     * The functions whose result keeps its input's keys, found once.
     *
     * @var array<string, ArgumentSelector>|null
     */
    private ?array $keyKeepers = null;

    /**
     * Each function's key parameters, and the ones among them in a glue,
     * which do not change between rounds.
     *
     * @var array<string, array{list<int>, list<int>}>
     */
    private array $keyParameters = [];

    /**
     * The functions that join with a glue, found once.
     *
     * @var array<string, int>|null
     */
    private ?array $glues = null;

    public function __construct(
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly AnalysisOptions $options,
        private readonly ParameterKeyReads $keyReads,
    ) {
    }

    /**
     * @param array<int, int|string> $keyBindings for a summary variant, the literal each bound parameter
     *                                            holds: see {@see FunctionSummary::variantKey()}
     */
    public function extract(
        FunctionContext $context,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
        array $keyBindings = [],
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
        $paramToReturnShape = [];
        $revertedResiduals = [];
        $paramToReturnEach = [];
        $imprecise = $parameterCount > $analysed;
        $forwarded = [];

        /** @var array<string, array<int, true>> $probeReads see AnalysisResult::$receiverReads */
        $probeReads = [];

        // A variant's bound key names the part a read under it takes.
        $partsKey = $keyBindings === [] ? $context->key : FunctionSummary::variantKey($context->key, $keyBindings);
        $parts = $this->parameterParts[$partsKey] ??= ParameterParts::of(
            $context->func,
            $this->keyKeepers ??= $this->analyzer->keyKeepers(),
            $keyBindings,
        );

        for ($index = 0; $index < $analysed; $index++) {
            $result = $this->analyzer->analyze(
                $context,
                $summaries,
                $properties,
                $scopes,
                $index,
                false,
                $parts[$index] ?? [],
                $keyBindings,
            );

            $paramToReturn[$index] = $result->returnTaint;

            foreach ($result->receiverReads as $property => $asked) {
                $probeReads[$property] = ($probeReads[$property] ?? []) + $asked;
            }

            foreach ($result->forwardedKeyParameters as $key) {
                $forwarded[$key] = true;
            }

            if ($result->revertedResiduals !== null && ! $result->revertedResiduals->isEmpty()) {
                $revertedResiduals[$index] = $result->revertedResiduals;
            }

            // And what it puts into the returned array, which a caller reads
            // the way it reads a local array.
            $returned = $result->returnShape ?? Shape::empty();
            $each = $returned->elements()[Shape::EACH] ?? null;

            // What comes back under the key it had: see Shape::EACH.
            if ($each !== null) {
                $paramToReturnEach[$index] = $each->flatten();
                $returned = $returned->withoutElement(Shape::EACH);
            }

            if (! $returned->isEmpty()) {
                $paramToReturnShape[$index] = $returned;
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
        //
        // This run also records the view of `$this` that a call on another
        // object compares. The view includes what the probe runs read there.
        $baseline = $this->analyzer->analyze(
            $context,
            $summaries,
            $properties,
            $scopes,
            null,
            false,
            [],
            $keyBindings,
            $probeReads,
        );

        [$keys, $glued] = $this->keyParameters[$context->key] ??= KeyParameters::of(
            $context->func,
            $this->glues ??= $this->analyzer->glueArguments(),
        );

        return new FunctionSummary(
            $keyBindings === [] ? $context->key : FunctionSummary::variantKey($context->key, $keyBindings),
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
            $paramToReturnShape,
            self::withoutEach($baseline->returnShape ?? Shape::empty()),
            $this->parameterKeys[$partsKey] ??= $this->keyReads->of($context->func, $keyBindings),
            $revertedResiduals,
            array_filter(
                $parts,
                static fn (int $index): bool => $index < $analysed,
                ARRAY_FILTER_USE_KEY,
            ),
            $paramToReturnEach,
            self::keyParameters($keys, [...array_keys($forwarded), ...$baseline->forwardedKeyParameters]),
            // A write to `$this` needs a run on the receiver only when the
            // method's own run holds its writes back. Otherwise that run
            // wrote the method's own objects, which every read of the
            // receiver sees.
            $baseline->receiverView?->withWrites(
                $baseline->receiverView->writes
                    && $this->analyzer->holdsBackReceiverWrites($context, [], $summaries),
            ),
            $glued,
        );
    }

    /**
     * A run that seeded no parameter has no element standing for each of the
     * parameter's, so one there goes under a computed key, which a read under
     * any key sees as well.
     */
    private static function withoutEach(Shape $shape): Shape
    {
        $each = $shape->elements()[Shape::EACH] ?? null;

        return $each === null ? $shape : $shape->withoutElement(Shape::EACH)->join(Shape::rest($each));
    }

    /**
     * The parameters a function uses as a key itself, and the ones it hands
     * on to a callee's key parameter.
     *
     * @param list<int> $own
     * @param list<int> $forwarded
     *
     * @return list<int>
     */
    private static function keyParameters(array $own, array $forwarded): array
    {
        $all = array_values(array_unique([...$own, ...$forwarded]));
        sort($all);

        return $all;
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
