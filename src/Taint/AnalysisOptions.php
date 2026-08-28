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
         * Whether a value whose origin the scan cannot see counts as unknown
         * rather than as clean.
         *
         * Off by default, because it is the difference between reporting flows
         * and reporting obligations, and the second is a much larger number:
         * WordPress's own standard says escape on output wherever the value
         * came from, and most output in a real plugin comes from somewhere the
         * scan cannot follow.
         *
         * On, the tool answers "is this value proven safe". Off, it answers
         * "can I trace this value to something dangerous". Both are useful and
         * they are not the same question, so the flag says which is being
         * asked. See {@see TaintKind::Unknown}.
         */
        public readonly bool $unknownProvenance = false,
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
        /**
         * Whether `include` and `require` join the two files' scopes.
         *
         * On by default — it is the shape WordPress themes are made of. The
         * escape hatch exists because it is also the change most likely to
         * connect request data to a template that has never been analysed in
         * context.
         */
        public readonly bool $followIncludes = true,
    ) {
    }

    public function assumeDynamicTainted(): bool
    {
        return $this->dynamicCalls === DynamicCallPolicy::Tainted;
    }
}
