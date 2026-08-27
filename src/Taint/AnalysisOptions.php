<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

final class AnalysisOptions
{
    /**
     * @param int $maxIterations per-function fixed point cap. Reaching it is a
     *                           loud warning, not a silent truncation.
     * @param int $maxTraceSteps traces longer than this are truncated in the
     *                           middle by the reporters, not here
     */
    public function __construct(
        public readonly bool $interprocedural = true,
        public readonly bool $assumeDynamicTainted = false,
        public readonly int $maxIterations = 64,
        public readonly int $maxTraceSteps = 64,
        public readonly int $maxSummarisedParameters = 8,
        public readonly int $maxInterproceduralRounds = 8,
    ) {
    }
}
