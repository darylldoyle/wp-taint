<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Scan\ScanResult;

/**
 * The machine handoff, and the format to give an agent.
 *
 * Console output is lossy by design — colour codes, collapsed traces, truncated
 * spans. This carries the full trace, the taint kinds at every step, the
 * fingerprints and the scan metadata, and it costs nothing extra to produce.
 *
 * Self-describing on purpose: the rule definition travels inline on every
 * finding rather than in a lookup table, so a reader coming to `findings.json`
 * cold needs no other context.
 */
final class JsonReporter implements Reporter
{
    public const SCHEMA_VERSION = '1.0';

    public function render(ScanResult $result, ReportOptions $options): string
    {
        $encoded = json_encode($this->toArray($result, $options), JSON_PRETTY_PRINT
            | JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
            | JSON_THROW_ON_ERROR);

        return $encoded . "\n";
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(ScanResult $result, ReportOptions $options): array
    {
        return [
            'schemaVersion' => self::SCHEMA_VERSION,
            'tool' => [
                'name' => 'wp-taint',
                'version' => $options->toolVersion,
            ],
            'scan' => [
                'root' => $result->root,
                'registries' => $result->registryNames,
                'filesScanned' => $result->filesScanned,
                'referenceFiles' => $result->referenceFiles,
                'referenceParseFailures' => $result->referenceParseFailures,
                'filesFailedToParse' => count($result->parseErrors),
                'interprocedural' => $result->interprocedural,
                'suppressedByBaseline' => $result->suppressedByBaseline,
                'suppressedInline' => $result->suppressedInline,
                // Excluded from any golden-file comparison: it is the one value
                // here that is not reproducible.
                'durationMs' => $result->durationMs,
            ],
            'parseFailures' => array_map(
                static fn (object $error): array => [
                    'file' => $error->file,
                    'line' => $error->line,
                    'message' => $error->message,
                ],
                $result->parseErrors,
            ),
            'unresolvedHooks' => $result->unresolvedHooks,
            'warnings' => array_map(
                static fn (object $warning): array => [
                    'file' => $warning->file,
                    'function' => $warning->functionName,
                    'message' => $warning->message,
                ],
                $result->warnings,
            ),
            'findings' => array_map(
                fn (Finding $finding): array => $this->finding($finding),
                $result->findings->all(),
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function finding(Finding $finding): array
    {
        return [
            'fingerprint' => $finding->fingerprint,
            'ruleId' => $finding->ruleId,
            'rule' => $finding->rule->toArray(),
            'severity' => $finding->severity->value,
            'kind' => $finding->kind->value,
            'location' => [
                'file' => $finding->file,
                'line' => $finding->line,
                'column' => $finding->column,
                'endColumn' => $finding->endColumn,
            ],
            'message' => $finding->message,
            'imprecise' => $finding->imprecise,
            'trace' => array_values(array_map(
                static fn (int $index, TraceStep $step): array => array_filter(
                    [
                        'step' => $index + 1,
                        'verb' => $step->verb->value,
                        'file' => $step->file,
                        'line' => $step->line,
                        'column' => $step->column,
                        'endColumn' => $step->endColumn,
                        'snippet' => $step->snippet,
                        'description' => $step->description,
                        'callee' => $step->callee,
                        'parameterIndex' => $step->parameterIndex,
                        'kinds' => $step->kinds->toStrings(),
                    ],
                    static fn (mixed $value): bool => $value !== null,
                ),
                array_keys($finding->trace),
                $finding->trace,
            )),
        ];
    }
}
