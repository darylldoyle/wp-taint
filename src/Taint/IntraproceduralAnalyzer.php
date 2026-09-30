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
     * Whether a run's property writes stay out of the shared map.
     *
     * A variant bound to a caller's literal key is one caller's, not the
     * body's. A receiver variant's writes are that receiver's, so they land,
     * with any key it binds too: they are that receiver's under that key.
     * A protected or private method that only other classes' methods call
     * runs only on the objects they name, as receiver variants, so its own
     * run, on an object of its own class, is not one that happens.
     *
     * @param array<int, int|string> $keyBindings
     */
    public function holdsBackWrites(FunctionContext $context, array $keyBindings): bool
    {
        if (isset($keyBindings[FunctionSummary::RECEIVER])) {
            return false;
        }

        if ($keyBindings !== []) {
            return true;
        }

        if ($context->className === null || $this->callGraph === null) {
            return false;
        }

        $flags = $context->func->flags;

        return ($flags & (Func::FLAG_PROTECTED | Func::FLAG_PRIVATE)) !== 0
            && ($flags & Func::FLAG_STATIC) === 0
            && $this->callGraph->calledOnlyFromOtherClasses($context->key);
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
        $properties = $seedParameterIndex === null && ! $this->holdsBackWrites($context, $keyBindings)
            ? $properties
            : $properties->sealed();
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
        ))->run();
    }
}
