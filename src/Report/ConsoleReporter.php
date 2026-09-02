<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisWarning;

/**
 * The primary human interface.
 *
 * Default output is two lines plus source and sink: enough to decide whether to
 * look closer. `--verbose` renders the full numbered trace with the source line
 * and a caret under the operand.
 */
final class ConsoleReporter implements Reporter
{
    /**
     * How many locations to name per distinct warning before summarising.
     *
     * Enough to go and look, few enough that a scan producing hundreds does not
     * bury its own findings.
     */
    private const MAX_WARNING_LOCATIONS = 5;

    public function __construct(private readonly Ansi $ansi)
    {
    }

    public function render(ScanResult $result, ReportOptions $options): string
    {
        $out = $this->renderHeader($result);

        foreach ($result->findings->orderedBySeverity() as $finding) {
            $out .= $this->renderFinding($finding, $options);
        }

        return $out . $this->renderSummary($result, $options);
    }

    /**
     * A banner marking where the findings start, so a reader dropped into a
     * long scroll can find the top. Only when there is something to report;
     * a clean scan has just its summary.
     */
    private function renderHeader(ScanResult $result): string
    {
        if ($result->findings->isEmpty()) {
            return '';
        }

        $rule = str_repeat('─', 61);
        $count = count($result->findings);

        return $rule . "\n"
            . '  ' . $this->ansi->bold('wp-taint') . $this->ansi->dim(sprintf(
                '  ·  %d finding%s, most severe first',
                $count,
                $count === 1 ? '' : 's',
            )) . "\n"
            . $rule . "\n\n";
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

        if ($finding->acknowledgement !== null) {
            $out .= '  ' . $this->ansi->dim(sprintf(
                'Suppressed in PHPCS with %s; reporting as a notice rather than a finding.',
                $finding->acknowledgement->sniff,
            )) . "\n";
        }

        if ($finding->imprecise) {
            $out .= '  ' . $this->ansi->dim('Imprecise: ' . $this->impreciseReason($finding)) . "\n";
        }

        return $out;
    }

    /**
     * The specific unresolved step on this finding's path, so the reader learns
     * what is uncertain without re-running with `--verbose`.
     */
    private function impreciseReason(Finding $finding): string
    {
        foreach ($finding->trace as $step) {
            if ($step->imprecise) {
                return sprintf('%s:%d  %s', $finding->file, $step->line, $step->description);
            }
        }

        return 'this path crossed something the engine could not resolve.';
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

    private function renderSummary(ScanResult $result, ReportOptions $options): string
    {
        $counts = $result->findings->countsBySeverity();
        $rule = str_repeat('─', 61);

        $line = sprintf(
            '  %s   %s   %s   %s   %s',
            $this->ansi->severity(Severity::Critical, ($counts['critical'] ?? 0) . ' critical'),
            $this->ansi->severity(Severity::High, ($counts['high'] ?? 0) . ' high'),
            $this->ansi->severity(Severity::Medium, ($counts['medium'] ?? 0) . ' medium'),
            $this->ansi->severity(Severity::Low, ($counts['low'] ?? 0) . ' low'),
            $this->ansi->severity(Severity::Notice, ($counts['notice'] ?? 0) . ' notice'),
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

        $acknowledged = 0;
        $imprecise = 0;

        foreach ($result->findings as $finding) {
            if ($finding->acknowledgement !== null) {
                $acknowledged++;
            }

            if ($finding->imprecise) {
                $imprecise++;
            }
        }

        if ($acknowledged > 0) {
            $out .= '  ' . $this->ansi->dim(sprintf(
                '%d downgraded to notice by a matching phpcs:ignore (--no-phpcs-suppressions for full severity)',
                $acknowledged,
            )) . "\n";
        }

        if ($imprecise > 0) {
            $out .= '  ' . $this->ansi->dim(sprintf(
                '%d crossed something the engine could not resolve, marked imprecise '
                    . '(--dynamic-calls tunes how unresolved calls are treated)',
                $imprecise,
            )) . "\n";
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

        $out .= $this->renderWarnings($result->warnings);

        return $out . $rule . "\n" . $this->renderExplainHint($result, $options);
    }

    /**
     * Warnings, with the function they are about.
     *
     * The warning has always carried a file and a function name and the
     * reporter printed neither, so three identical lines saying "results for
     * this function may be incomplete" left no way to find out which function.
     * Repeats are grouped for the same reason: the count is the useful part,
     * the wall of identical lines is not.
     *
     * @param list<AnalysisWarning> $warnings
     */
    private function renderWarnings(array $warnings): string
    {
        if ($warnings === []) {
            return '';
        }

        /** @var array<string, list<AnalysisWarning>> $grouped */
        $grouped = [];

        foreach ($warnings as $warning) {
            $grouped[$warning->message][] = $warning;
        }

        $out = '';

        foreach ($grouped as $message => $group) {
            $out .= '  ' . $this->ansi->red('warning: ' . $message) . "\n";

            foreach (array_slice($group, 0, self::MAX_WARNING_LOCATIONS) as $warning) {
                $out .= '    ' . $this->ansi->dim(sprintf(
                    '%s  %s()',
                    $warning->file,
                    $warning->functionName,
                )) . "\n";
            }

            $remaining = count($group) - self::MAX_WARNING_LOCATIONS;

            if ($remaining > 0) {
                $out .= '    ' . $this->ansi->dim(sprintf('and %d more', $remaining)) . "\n";
            }
        }

        return $out;
    }

    /**
     * The footer, shown once rather than under every finding.
     *
     * Two hints belonged under each finding and said the same thing every time,
     * which is noise. They live here now: how to see the full trace, and how to
     * ask why a value is tainted.
     *
     * The explain hint is built from the first finding rather than described,
     * because a command someone can paste cannot be wrong about its own syntax.
     * It used to read "run with --verbose ... or --explain", which was wrong
     * twice: `explain` is a command, not an option, so `scan --explain` fails,
     * and it needs `--scope` or it analyses the one file alone and reports clean
     * on anything whose taint arrives through an include or a hook.
     */
    private function renderExplainHint(ScanResult $result, ReportOptions $options): string
    {
        $findings = $result->findings->all();
        $first = $findings[0] ?? null;

        if ($first === null || $options->verbose) {
            return '';
        }

        return "\n" . $this->ansi->dim('  Run with --verbose for the full source-to-sink trace on each finding.')
            . "\n\n"
            . $this->ansi->dim('  Why is a value tainted? Ask about the line:') . "\n"
            . $this->ansi->dim(sprintf(
                "  wp-taint explain %s:%d --scope=%s",
                rtrim($result->root, '/') . '/' . ltrim($first->file, '/'),
                $first->line,
                $result->root,
            )) . "\n";
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
