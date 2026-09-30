<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\IncludeGraph;
use Enshrined\WpTaint\Hooks\RestRouteTable;
use Enshrined\WpTaint\Registry\ArgumentSelector;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Func;

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
        /**
         * The scan's REST routes: which callbacks a permission callback
         * entitles, and what each route's schema does to its parameters.
         */
        private readonly ?RestRouteTable $restRoutes = null,
        /**
         * The functions only an administrator can reach, whose option writes
         * store nothing a request chose.
         */
        private readonly ?AdministratorReach $administrators = null,
    ) {
    }

    /**
     * The functions whose result keeps its input's keys: see
     * {@see Registry::keyKeepers()}.
     *
     * @return array<string, ArgumentSelector>
     */
    public function keyKeepers(): array
    {
        return $this->registry->keyKeepers();
    }

    /**
     * The functions that join with a glue: see {@see Registry::glueArguments()}.
     *
     * @return array<string, int>
     */
    public function glueArguments(): array
    {
        return $this->registry->glueArguments();
    }

    /**
     * Whether a run's property writes stay out of the shared map.
     *
     * A variant bound to a caller's literal key is one caller's, not the
     * body's. A receiver variant's writes are that receiver's, so they land,
     * with any key it binds too: they are that receiver's under that key.
     *
     * @param array<int, int|string> $keyBindings
     */
    public function holdsBackWrites(array $keyBindings): bool
    {
        return $keyBindings !== [] && ! isset($keyBindings[FunctionSummary::RECEIVER]);
    }

    /**
     * Whether a method's own run keeps its writes to `$this` out of the
     * shared map, and lands the rest.
     *
     * A protected or private method that only other classes' methods call by
     * name runs as a receiver variant on each object they name. A call that
     * names no object, such as one on a parameter, runs a variant on the
     * method's own objects: see {@see FunctionAnalysis::heldBackReceiverOf()}.
     * Its own run is not one that happens. So its writes to `$this` are held
     * back, and so are its writes to an object a property of `$this` holds,
     * which depends on the object too. Its summary then says it wrote
     * `$this`, so every call runs a variant, and the variants land those
     * writes. See {@see ReceiverView::$writes}.
     *
     * Its other writes land: an option, a static property, an object made
     * with `new` or handed in. The method makes those wherever it runs, and
     * its own summary carries only the writes a parameter reaches.
     *
     * Not past the method's receiver cap. A call there applies the own
     * summary and runs no variant, so the own run's writes are the only ones.
     *
     * @param array<int, int|string> $keyBindings
     */
    public function holdsBackReceiverWrites(
        FunctionContext $context,
        array $keyBindings,
        SummaryTable $summaries,
    ): bool {
        if ($keyBindings !== [] || $context->className === null || $this->callGraph === null) {
            return false;
        }

        $flags = $context->func->flags;

        return ($flags & (Func::FLAG_PROTECTED | Func::FLAG_PRIVATE)) !== 0
            && ($flags & Func::FLAG_STATIC) === 0
            && $this->callGraph->calledOnlyFromOtherClasses($context->key)
            && ! $summaries->isCapped($context->key, SummaryTable::RECEIVER_VARIANT);
    }

    /**
     * @param int|null               $seedParameterIndex when set, that parameter is seeded
     *                                                    with every taint kind and no real
     *                                                    sources are used — this is how
     *                                                    summaries are extracted
     * @param list<list<int|string>> $seedParts          the parts of the seeded parameter to seed
     *                                                    apart: see {@see ParameterParts}
     * @param array<int, int|string> $keyBindings        for a summary variant, the literal each
     *                                                    bound parameter holds: see
     *                                                    {@see FunctionSummary::variantKey()}
     */
    public function analyze(
        FunctionContext $context,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
        ?int $seedParameterIndex = null,
        bool $collectFindings = true,
        array $seedParts = [],
        array $keyBindings = [],
    ): AnalysisResult {
        // A probe run asks what one parameter reaches; it does not observe the
        // body as written, so nothing it writes belongs in the shared property
        // map. See PropertyTaintMap::$sealed. Nor does a run of a summary
        // variant, whose bound key is one caller's, not the body's.
        $sealed = $seedParameterIndex !== null || $this->holdsBackWrites($keyBindings);
        $properties = $sealed ? $properties->sealed() : $properties;
        $receivers = new ReceiverResolver($this->functions->declaredTypes());

        return (new FunctionAnalysis(
            $context,
            $this->registry,
            $this->functions,
            $this->resolver,
            // Built per run: it consults the property map, which the caller
            // owns and which grows as the interprocedural rounds proceed.
            new LiteralAnalyzer($this->registry, $properties, $receivers),
            $summaries,
            $properties,
            $scopes,
            $this->includes,
            $receivers,
            $this->options,
            $seedParameterIndex,
            $collectFindings,
            $this->callGraph,
            $this->shortcodeCallbacks,
            $this->printedReturns,
            $this->restRoutes,
            $this->administrators,
            $seedParts,
            $keyBindings,
            ! $sealed && $this->holdsBackReceiverWrites($context, $keyBindings, $summaries),
        ))->run();
    }
}
