<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\RuleDefinition;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Scan\ScanResult;

/**
 * SARIF 2.1.0, with `codeFlows` populated from the traces.
 *
 * The code flow is the whole point. Emitting SARIF without it degrades to a
 * flat list no better than the console output, and wastes the format. With it,
 * Trail of Bits' SARIF Explorer and Microsoft's SARIF Viewer both render a
 * clickable source-to-sink walk — which is exactly the triage workflow the
 * tuning phase needs.
 */
final class SarifReporter implements Reporter
{
    private const SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/'
        . 'sarif-schema-2.1.0.json';

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
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'wp-taint',
                            'version' => $options->toolVersion,
                            'informationUri' => 'https://github.com/darylldoyle/wp-taint',
                            'rules' => $this->rules($result),
                        ],
                    ],
                    // Lets viewers resolve relative paths against the local
                    // workspace without prompting for a root.
                    'originalUriBaseIds' => [
                        'SRCROOT' => ['uri' => 'file://' . rtrim($result->root, '/') . '/'],
                    ],
                    'results' => array_map(
                        fn (Finding $finding): array => $this->result($finding),
                        $result->findings->all(),
                    ),
                    'invocations' => [
                        [
                            'executionSuccessful' => $result->parseErrors === [],
                            'toolExecutionNotifications' => array_map(
                                static fn (object $error): array => [
                                    'level' => 'error',
                                    'message' => ['text' => $error->message],
                                    'locations' => [
                                        [
                                            'physicalLocation' => [
                                                'artifactLocation' => [
                                                    'uri' => $error->file,
                                                    'uriBaseId' => 'SRCROOT',
                                                ],
                                            ],
                                        ],
                                    ],
                                ],
                                $result->parseErrors,
                            ),
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rules(ScanResult $result): array
    {
        /** @var array<string, RuleDefinition> $definitions */
        $definitions = [];

        /** @var array<string, string> $levels */
        $levels = [];

        /** @var array<string, string> $severities */
        $severities = [];

        foreach ($result->findings as $finding) {
            $definitions[$finding->ruleId] = $finding->rule;
            $levels[$finding->ruleId] = $finding->severity->sarifLevel();
            $severities[$finding->ruleId] = $finding->severity->securitySeverity();
        }

        ksort($definitions);

        $rules = [];

        foreach ($definitions as $id => $definition) {
            $tags = ['security', 'wordpress'];

            if ($definition->cwe !== null) {
                $tags[] = 'external/cwe/' . strtolower(str_replace('CWE-', 'cwe-', $definition->cwe));
            }

            $rules[] = [
                'id' => $id,
                'name' => $this->pascalCase($id),
                'shortDescription' => ['text' => $definition->title],
                'fullDescription' => ['text' => $definition->description],
                'help' => [
                    'text' => $definition->remediation,
                    'markdown' => sprintf(
                        "**%s**\n\n%s\n\n**Remediation.** %s",
                        $definition->title,
                        $definition->description,
                        $definition->remediation,
                    ),
                ],
                'defaultConfiguration' => ['level' => $levels[$id] ?? 'warning'],
                'properties' => [
                    'tags' => $tags,
                    'security-severity' => $severities[$id] ?? '5.0',
                ],
            ];
        }

        return $rules;
    }

    /**
     * @return array<string, mixed>
     */
    private function result(Finding $finding): array
    {
        return [
            'ruleId' => $finding->ruleId,
            'level' => $finding->severity->sarifLevel(),
            'message' => ['text' => $finding->message],
            'locations' => [$this->location($finding->file, $finding->line, $finding->column, $finding->endColumn)],
            'partialFingerprints' => [
                'wpTaintFingerprint' => $finding->fingerprint,
            ],
            'properties' => [
                // SARIF has no `critical`, so the real severity travels here.
                'problemSeverity' => $finding->severity->value,
                'securitySeverity' => $finding->severity->securitySeverity(),
                'taintKind' => $finding->kind->value,
                'imprecise' => $finding->imprecise,
            ],
            'codeFlows' => [
                [
                    'message' => ['text' => 'Untrusted input reaches the sink along this path.'],
                    'threadFlows' => [
                        [
                            'locations' => array_map(
                                fn (TraceStep $step): array => $this->threadFlowLocation($step),
                                $finding->trace,
                            ),
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function threadFlowLocation(TraceStep $step): array
    {
        return [
            'nestingLevel' => 0,
            'location' => [
                'physicalLocation' => $this->location(
                    $step->file,
                    $step->line,
                    $step->column,
                    $step->endColumn,
                )['physicalLocation'],
                'message' => ['text' => $step->description],
            ],
            'properties' => [
                'verb' => $step->verb->value,
                'kinds' => $step->kinds->toStrings(),
            ],
        ];
    }

    /**
     * @return array{physicalLocation: array<string, mixed>}
     */
    private function location(string $file, int $line, int $column, ?int $endColumn): array
    {
        $region = ['startLine' => max(1, $line)];

        if ($column > 0) {
            $region['startColumn'] = $column;

            if ($endColumn !== null && $endColumn > $column) {
                $region['endColumn'] = $endColumn;
            }
        }

        return [
            'physicalLocation' => [
                'artifactLocation' => [
                    'uri' => $file,
                    'uriBaseId' => 'SRCROOT',
                ],
                'region' => $region,
            ],
        ];
    }

    private function pascalCase(string $ruleId): string
    {
        $parts = preg_split('/[.\-_]/', $ruleId);

        return implode('', array_map(
            static fn (string $part): string => ucfirst($part),
            $parts === false ? [$ruleId] : $parts,
        ));
    }
}
