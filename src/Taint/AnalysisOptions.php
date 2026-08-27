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
        /**
         * What an unresolved call is assumed to do. `--assume-dynamic-tainted`
         * is the old spelling of {@see DynamicCallPolicy::Tainted} and still
         * works.
         */
        public readonly DynamicCallPolicy $dynamicCalls = DynamicCallPolicy::Propagate,
        public readonly int $maxIterations = 64,
        public readonly int $maxTraceSteps = 64,
        public readonly int $maxSummarisedParameters = 8,
        /**
         * Rounds are cheap when they are not needed: the loop exits as soon as
         * nothing changes, so a generous cap costs nothing on code that settles
         * early. It only bites where the alternative is silently incomplete
         * summaries, which is the worse outcome.
         *
         * Measured on the corpus: real plugins settle in 5 to 8 rounds. The
         * previous cap of 8 was clipping eleven of the fifty.
         */
        public readonly int $maxInterproceduralRounds = 32,
    ) {
    }

    public function assumeDynamicTainted(): bool
    {
        return $this->dynamicCalls === DynamicCallPolicy::Tainted;
    }
}
