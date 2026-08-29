<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\Finding;

final class AnalysisResult
{
    /**
     * @param list<Finding>         $findings
     * @param list<SinkReference>   $sinksReached sinks the seeded taint reached
     * @param array<int, TaintSet>  $byRefTaint   final taint of each by-reference parameter
     * @param list<AnalysisWarning> $warnings
     */
    public function __construct(
        public readonly array $findings,
        public readonly TaintSet $returnTaint,
        public readonly array $sinksReached,
        public readonly bool $imprecise,
        public readonly array $byRefTaint = [],
        public readonly array $warnings = [],
        /**
         * The converged taint state, kept only so `explain` and
         * `--dump-taint-graph` can read it. Nothing on the analysis path
         * depends on it.
         */
        public readonly ?TaintState $state = null,
        /**
         * Every `return` in this function yielded a string with a literal
         * fragment in it.
         *
         * Carried so {@see LiteralAnchor} can see through a call. The anchor
         * that makes an option name safe is very often three frames away —
         * WooCommerce builds
         * `'woocommerce_onboarding_..._async_' . $job_id` in one method, passes
         * it to a constructor, and writes it from a property in a third — and a
         * check that stops at the call boundary calls every one of those a
         * finding.
         */
        public readonly bool $returnAnchored = false,
        /**
         * Properties the seeded parameter was written into.
         *
         * The write half of what a caller needs, and the counterpart to
         * `$sinksReached`. A probe run's map is sealed, so the write itself
         * goes nowhere — this records that it happened, and the caller applies
         * the taint it actually passed.
         *
         * @var list<array{0: string|null, 1: string}> class name (null when
         *                                             unresolved) and property
         */
        public readonly array $propertiesReached = [],
    ) {
    }
}
