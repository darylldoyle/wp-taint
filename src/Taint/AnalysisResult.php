<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\Finding;

final class AnalysisResult
{
    /**
     * @param list<Finding>         $findings
     * @param list<SinkReference>   $sinksReached sinks the seeded taint reached
     * @param list<AnalysisWarning> $warnings
     * @param list<string>          $resolvedCleanSites `relative/path.php:line` for sinks the engine
     *                                                  understood completely and found clean
     */
    public function __construct(
        public readonly array $findings,
        public readonly TaintSet $returnTaint,
        public readonly array $sinksReached,
        public readonly bool $imprecise,
        public readonly array $warnings = [],
        public readonly array $resolvedCleanSites = [],
        /**
         * The converged taint state, kept only so `explain` and
         * `--dump-taint-graph` can read it. Nothing on the analysis path
         * depends on it.
         */
        public readonly ?TaintState $state = null,
    ) {
    }
}
