<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cfg\ParseError;
use Enshrined\WpTaint\Finding\FindingCollection;
use Enshrined\WpTaint\Taint\AnalysisWarning;

final class ScanResult
{
    /**
     * @param list<ParseError>      $parseErrors
     * @param list<AnalysisWarning> $warnings
     * @param list<string>          $registryNames
     * @param list<string>          $unresolvedHooks
     */
    public function __construct(
        public readonly FindingCollection $findings,
        public readonly array $parseErrors,
        public readonly int $filesScanned,
        public readonly array $warnings,
        public readonly string $root,
        public readonly array $registryNames,
        public readonly bool $interprocedural,
        public readonly int $durationMs,
        public readonly array $unresolvedHooks = [],
        public readonly int $suppressedByBaseline = 0,
        public readonly int $suppressedInline = 0,
        /**
         * Files parsed from `--include-path` for their symbols only.
         *
         * Reported separately from `filesScanned` because they are context, not
         * work: a run that says it scanned 30,000 files when the user pointed it
         * at a 40-file plugin is lying about what it looked at.
         */
        public readonly int $referenceFiles = 0,
        public readonly int $referenceParseFailures = 0,
    ) {
    }

    public function withFindings(FindingCollection $findings, int $suppressedByBaseline, int $suppressedInline): self
    {
        return new self(
            $findings,
            $this->parseErrors,
            $this->filesScanned,
            $this->warnings,
            $this->root,
            $this->registryNames,
            $this->interprocedural,
            $this->durationMs,
            $this->unresolvedHooks,
            $suppressedByBaseline,
            $suppressedInline,
            $this->referenceFiles,
            $this->referenceParseFailures,
        );
    }

    public function hasParseErrors(): bool
    {
        return $this->parseErrors !== [];
    }
}
