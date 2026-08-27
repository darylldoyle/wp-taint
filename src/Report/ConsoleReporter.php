<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Scan\ScanResult;

/**
 * The primary human interface.
 *
 * Default output is two lines plus source and sink: enough to decide whether to
 * look closer. `--verbose` renders the full numbered trace with the source line
 * and a caret under the operand.
 */
final class ConsoleReporter implements Reporter
{
    public function __construct(private readonly Ansi $ansi)
    {
    }

    public function render(ScanResult $result, ReportOptions $options): string
    {
        $out = '';

        foreach ($result->findings->groupedByFile() as $findings) {
            foreach ($findings as $finding) {
                $out .= $this->renderFinding($finding, $options);
            }
        }

        return $out . $this->renderSummary($result);
    }

    private function renderFinding(Finding $finding, ReportOptions $options): string
    {
        $header = sprintf(
            "%s  %s\n  %s:%d:%d  %s\n",
            $this->ansi->severity($finding->severity, str_pad(strtoupper($finding->severity->value), 8)),
            $this->ansi->bold($finding->ruleId),
            $finding->file,
            $finding->line,
            $finding->column,
            $this->sinkLabel($finding),
        );

        $body = $options->verbose
            ? $this->renderVerbose($finding, $options)
            : $this->renderCompact($finding);

        return $header . $body . "\n";
    }

    private function sinkLabel(Finding $finding): string
    {
        if ($finding->sinkIdentity !== '') {
            return $this->ansi->dim($finding->sinkIdentity);
        }

        $last = $finding->trace[count($finding->trace) - 1] ?? null;

        return $this->ansi->dim($last === null ? $finding->kind->value : self::truncate($last->snippet, 72));
    }

    private function renderCompact(Finding $finding): string
    {
        $first = $finding->trace[0] ?? null;
        $last = $finding->trace[count($finding->trace) - 1] ?? null;

        $out = "\n";

        if ($first !== null && $first !== $last) {
            $out .= sprintf(
                "    %s  :%d:%d  %s\n",
                $this->ansi->cyan(str_pad('source', 8)),
                $first->line,
                $first->column,
                self::truncate($first->snippet, 64),
            );
        }

        if ($last !== null) {
            $out .= sprintf(
                "    %s  :%d:%d  %s\n",
                $this->ansi->cyan(str_pad('sink', 8)),
                $last->line,
                $last->column,
                self::truncate($last->snippet, 64),
            );
        }

        $out .= "\n  " . $finding->message . "\n";

        if ($finding->imprecise) {
            $out .= '  ' . $this->ansi->dim(
                'This path crossed something the engine could not resolve; it may be a false positive.',
            ) . "\n";
        }

        $out .= '  ' . $this->ansi->dim('Run with --verbose for the full path, or --explain for why.') . "\n";

        return $out;
    }

    private function renderVerbose(Finding $finding, ReportOptions $options): string
    {
        $out = "\n  " . $finding->message . "\n\n";

        $steps = $finding->trace;
        $total = count($steps);
        $collapseAfter = $options->collapseTracesLongerThan;

        foreach ($steps as $index => $step) {
            $shouldCollapse = ! $options->traceFull
                && $total > $collapseAfter
                && $index === 3;

            if ($shouldCollapse) {
                $hidden = $total - 6;
                $out .= sprintf(
                    "   %s\n\n",
                    $this->ansi->dim(sprintf('... %d intermediate steps (--trace-full to expand)', $hidden)),
                );
            }

            if (! $options->traceFull && $total > $collapseAfter && $index >= 3 && $index < $total - 3) {
                continue;
            }

            $out .= $this->renderStep($index + 1, $step);
        }

        $out .= $this->renderRemediation($finding);

        return $out;
    }

    private function renderStep(int $number, TraceStep $step): string
    {
        $out = sprintf(
            "  %2d. %s %s:%d:%d\n",
            $number,
            $this->ansi->cyan(str_pad($step->verb->value, 12)),
            $step->file,
            $step->line,
            $step->column,
        );

        if ($step->snippet !== '') {
            $out .= '      ' . $step->snippet . "\n";

            $caret = $this->caret($step);

            if ($caret !== null) {
                $out .= '      ' . $this->ansi->dim($caret) . "\n";
            }
        }

        $out .= '      ' . $this->wrap($step->description, 66, '      ') . "\n";

        if (! $step->kinds->isEmpty()) {
            $out .= '      ' . $this->ansi->dim('Kinds: ' . $step->kinds->describe()) . "\n";
        }

        return $out . "\n";
    }

    /**
     * A caret line under the operand's column span.
     *
     * Omitted rather than guessed when the span is unavailable: php-cfg gives
     * no attributes at all for synthetic ops, and a caret under the wrong
     * characters is worse than no caret.
     */
    private function caret(TraceStep $step): ?string
    {
        if ($step->column < 1 || $step->endColumn === null || $step->endColumn <= $step->column) {
            return null;
        }

        // The snippet is trimmed, so the column has to be rebased onto it.
        $indent = strlen($step->snippet) - strlen(ltrim($step->snippet));
        $start = $step->column - 1 - $indent;

        if ($start < 0 || $start >= strlen($step->snippet)) {
            return null;
        }

        $length = min($step->endColumn - $step->column, strlen($step->snippet) - $start);

        if ($length < 1) {
            return null;
        }

        return str_repeat(' ', $start) . str_repeat('^', $length);
    }

    private function renderRemediation(Finding $finding): string
    {
        $out = '  ' . $this->ansi->bold('Fix') . "\n";
        $out .= '    ' . $this->wrap($finding->rule->remediation, 68, '    ') . "\n\n";
        $out .= '  ' . $this->ansi->bold('Suppress') . "\n";
        $out .= '    ' . $this->ansi->dim(
            sprintf('// wp-taint-ignore-next-line %s -- <reason>', $finding->ruleId),
        ) . "\n";

        return $out;
    }

    private function renderSummary(ScanResult $result): string
    {
        $counts = $result->findings->countsBySeverity();
        $rule = str_repeat('─', 61);

        $line = sprintf(
            '  %s   %s   %s   %s',
            $this->ansi->severity(Severity::Critical, ($counts['critical'] ?? 0) . ' critical'),
            $this->ansi->severity(Severity::High, ($counts['high'] ?? 0) . ' high'),
            $this->ansi->severity(Severity::Medium, ($counts['medium'] ?? 0) . ' medium'),
            $this->ansi->severity(Severity::Low, ($counts['low'] ?? 0) . ' low'),
        );

        $out = $rule . "\n" . $line . "\n";
        $out .= sprintf(
            "  %d finding%s in %d file%s · %d file%s scanned · %.1fs\n",
            count($result->findings),
            count($result->findings) === 1 ? '' : 's',
            count($result->findings->files()),
            count($result->findings->files()) === 1 ? '' : 's',
            $result->filesScanned,
            $result->filesScanned === 1 ? '' : 's',
            $result->durationMs / 1000,
        );

        if ($result->suppressedByBaseline > 0) {
            $out .= sprintf(
                "  %d finding%s suppressed by baseline\n",
                $result->suppressedByBaseline,
                $result->suppressedByBaseline === 1 ? '' : 's',
            );
        }

        if ($result->suppressedInline > 0) {
            $out .= sprintf(
                "  %d finding%s suppressed inline\n",
                $result->suppressedInline,
                $result->suppressedInline === 1 ? '' : 's',
            );
        }

        // Always shown when non-zero, at any verbosity. A silently skipped file
        // is a silent false negative.
        if ($result->parseErrors !== []) {
            $out .= '  ' . $this->ansi->red(sprintf(
                '%d file%s failed to parse (run --parse-report)',
                count($result->parseErrors),
                count($result->parseErrors) === 1 ? '' : 's',
            )) . "\n";
        }

        if ($result->unresolvedHooks !== []) {
            $out .= '  ' . $this->ansi->dim(sprintf(
                '%d hook registration%s could not be resolved to a callback',
                count($result->unresolvedHooks),
                count($result->unresolvedHooks) === 1 ? '' : 's',
            )) . "\n";
        }

        foreach ($result->warnings as $warning) {
            $out .= '  ' . $this->ansi->red('warning: ' . $warning->message) . "\n";
        }

        return $out . $rule . "\n";
    }

    private function wrap(string $text, int $width, string $indent): string
    {
        return str_replace("\n", "\n" . $indent, wordwrap($text, $width, "\n", false));
    }

    private static function truncate(string $text, int $length): string
    {
        return strlen($text) <= $length ? $text : substr($text, 0, $length - 3) . '...';
    }
}
