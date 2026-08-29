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
         * On by default. WordPress's own standard is escape on output wherever
         * the value came from, so output nothing vouches for is worth a look
         * even when no flow reaches it — the reader can dismiss it in a second
         * if they know the value is safe, and cannot dismiss what was never
         * shown to them.
         *
         * On, the tool answers "is this value proven safe". Off, it answers
         * "can I trace this value to something dangerous". Both are useful and
         * they are not the same question, so `--no-unknown-provenance` says
         * when the second is the one being asked.
         *
         * It costs nothing to run: seeding a marker on an entry point's
         * parameters is not extra work for the fixed point, and a 926-file
         * scan measures the same either way. What it costs is findings, all at
         * `low`, which is below the default `--fail-on` and so cannot fail a
         * build on its own. See {@see TaintKind::Unknown}.
         */
        public readonly bool $unknownProvenance = true,
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
