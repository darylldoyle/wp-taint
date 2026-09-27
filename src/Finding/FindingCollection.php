<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

use Countable;
use Enshrined\WpTaint\Taint\TaintKind;
use IteratorAggregate;
use Traversable;

/**
 * An ordered, de-duplicated set of findings.
 *
 * @implements IteratorAggregate<int, Finding>
 */
final class FindingCollection implements IteratorAggregate, Countable
{
    /**
     * @param list<Finding> $findings
     */
    private function __construct(private readonly array $findings)
    {
    }

    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * @param list<Finding> $findings
     */
    public static function fromArray(array $findings): self
    {
        return (new self($findings))->normalised();
    }

    /**
     * @return list<Finding>
     */
    public function all(): array
    {
        return $this->findings;
    }

    public function getIterator(): Traversable
    {
        yield from $this->findings;
    }

    public function count(): int
    {
        return count($this->findings);
    }

    public function isEmpty(): bool
    {
        return $this->findings === [];
    }

    public function merge(self $other): self
    {
        return (new self([...$this->findings, ...$other->findings]))->normalised();
    }

    /**
     * @param callable(Finding): bool $predicate
     */
    public function filter(callable $predicate): self
    {
        return new self(array_values(array_filter($this->findings, $predicate)));
    }

    /**
     * Replace each finding with a transformed copy, keeping the count and the
     * order. Used to downgrade a finding in place, e.g. an author-acknowledged
     * one, without disturbing anything else.
     *
     * @param callable(Finding): Finding $transform
     */
    public function map(callable $transform): self
    {
        return new self(array_map($transform, $this->findings));
    }

    public function withMinimumSeverity(Severity $minimum): self
    {
        return $this->filter(static fn (Finding $finding): bool => $finding->severity->atLeast($minimum));
    }

    public function hasAtLeast(Severity $severity): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->severity->atLeast($severity)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Drop a finding when a more specific rule already reported the same defect
     * at the same place.
     *
     * Two overlaps are intentional and both need resolving:
     *
     * - `wp.sqli.unprepared-query` is a shape rule that exists to catch queries
     *   the dataflow engine could not reach. When taint *did* reach one, the
     *   taint finding wins: it carries a real source-to-sink trace.
     * - `wp.sqli.wpdb-query` fires on the outer `$wpdb->get_results()` of a
     *   `get_results($wpdb->prepare($built, ...))`. So does
     *   `wp.sqli.prepare-non-literal`, on the same line. The prepare rule wins:
     *   it names the actual defect and the actual fix.
     *
     * Reporting one defect twice is how a scanner earns a reputation for noise.
     *
     * But a line must never report less than it holds. For each pair on a
     * line:
     *
     * - The specific finding wins when it is at least as severe.
     * - When it is less severe and both traces start at the same place, they
     *   tell one story at two severities. The specific finding stays and takes
     *   the higher severity. A filter callback that appends raw input to an
     *   escaped value makes it both voided and raw: escape-voided names the
     *   fix, and the raw flow says how severe it is.
     * - Otherwise they are two flows, and both stay. A request value can
     *   reach an echo raw while a filtered option reaches it voided.
     *
     * @param array<string, list<string>> $precedence superseded rule id => rule
     *                                                ids that supersede it; an
     *                                                empty list means any other
     *                                                rule supersedes it
     */
    public function withRulePrecedence(array $precedence): self
    {
        $byLine = [];

        foreach ($this->findings as $finding) {
            $byLine[$finding->file . ':' . $finding->line][] = $finding;
        }

        $kept = [];

        foreach ($this->findings as $finding) {
            $source = self::sourceOf($finding);
            $raisedBy = null;

            foreach ($byLine[$finding->file . ':' . $finding->line] ?? [] as $other) {
                $sameStory = $source !== null && self::sourceOf($other) === $source;

                // A specific finding says what this one says, as severely or
                // about the same flow.
                if (
                    self::supersedes($precedence, $other, $finding)
                    && ($sameStory || $other->severity->atLeast($finding->severity))
                ) {
                    continue 2;
                }

                // This one stands for a more severe finding about the same
                // flow, so it reports at that severity.
                if (
                    $sameStory
                    && self::supersedes($precedence, $finding, $other)
                    && ! $finding->severity->atLeast($other->severity)
                    && ($raisedBy === null || ! $raisedBy->severity->atLeast($other->severity))
                ) {
                    $raisedBy = $other;
                }
            }

            $kept[] = $raisedBy === null ? $finding : $finding->raisedBy($raisedBy);
        }

        return new self($kept);
    }

    /**
     * Whether the precedence lets one finding on a line replace another.
     *
     * The wildcard, "any other finding here supersedes this one", stays scoped
     * to the kind, so an html finding at the same line cannot silence an sql
     * one. A rule *named* as superseding matches across kinds: the pairs in the
     * map are pairs because they say the same thing about the same line,
     * whatever kind each carries.
     *
     * @param array<string, list<string>> $precedence
     */
    private static function supersedes(array $precedence, Finding $winner, Finding $loser): bool
    {
        $supersededBy = $precedence[$loser->ruleId] ?? null;

        if ($supersededBy === null || $winner === $loser || $winner->ruleId === $loser->ruleId) {
            return false;
        }

        return $supersededBy === []
            ? $winner->kind === $loser->kind
            : in_array($winner->ruleId, $supersededBy, true);
    }

    /**
     * Where a finding's flow starts: the first step of its trace that names a
     * place, to the column. Two flows can start on one line:
     * `$c ? $_GET['a'] : apply_filters( 'x', $v )`.
     *
     * A join has no place of its own, so a trace that starts at one starts at
     * the step after it. Null for a trace with no place at all, which says
     * nothing about whether two findings share a flow.
     */
    private static function sourceOf(Finding $finding): ?string
    {
        foreach ($finding->trace as $step) {
            if ($step->line > 0) {
                return $step->file . ':' . $step->line . ':' . $step->column;
            }
        }

        return null;
    }

    /**
     * @return array<string, int>
     */
    public function countsBySeverity(): array
    {
        $counts = [
            Severity::Critical->value => 0,
            Severity::High->value => 0,
            Severity::Medium->value => 0,
            Severity::Low->value => 0,
            Severity::Notice->value => 0,
        ];

        foreach ($this->findings as $finding) {
            $counts[$finding->severity->value]++;
        }

        return $counts;
    }

    /**
     * @return list<string>
     */
    public function files(): array
    {
        $files = [];

        foreach ($this->findings as $finding) {
            $files[$finding->file] = true;
        }

        $names = array_keys($files);
        sort($names);

        return $names;
    }

    /**
     * @return array<string, list<Finding>>
     */
    public function groupedByFile(): array
    {
        $grouped = [];

        foreach ($this->findings as $finding) {
            $grouped[$finding->file][] = $finding;
        }

        ksort($grouped);

        return $grouped;
    }

    /**
     * Most severe first, then the canonical file/line order within a severity.
     *
     * For the console, where the thing a reader wants is the criticals, and
     * scrolling a file-ordered list to find them is the complaint this answers.
     * The JSON and SARIF reports keep the canonical order, which tools sort
     * themselves.
     *
     * @return list<Finding>
     */
    public function orderedBySeverity(): array
    {
        $findings = $this->findings;

        usort($findings, static function (Finding $a, Finding $b): int {
            $bySeverity = $b->severity->rank() <=> $a->severity->rank();

            if ($bySeverity !== 0) {
                return $bySeverity;
            }

            // Within one effective tier, order by the severity a finding was
            // reduced from, most severe first: a critical SQL issue acknowledged
            // down to a notice must not sit below a low unknown-output notice. A
            // finding that was never acknowledged reports its own severity here,
            // so this is a no-op outside the notice tier.
            $byOrigin = self::originSeverity($b)->rank() <=> self::originSeverity($a)->rank();

            return $byOrigin !== 0 ? $byOrigin : $a->compareTo($b);
        });

        return $findings;
    }

    /**
     * The severity a finding started at: the one it was acknowledged down from,
     * or its own when it was never acknowledged.
     */
    private static function originSeverity(Finding $finding): Severity
    {
        return $finding->acknowledgement->originalSeverity ?? $finding->severity;
    }

    public function hasKind(TaintKind $kind): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->kind === $kind) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sort and de-duplicate. Two findings with the same rule, location and
     * fingerprint are the same finding however many analysis passes produced
     * them.
     *
     * They can still arrive with *different traces*: a sink can be genuinely
     * reachable by more than one path, and which path is found first depends on
     * the order functions were analysed — which under `--jobs` is whatever the
     * scheduler picked. "First wins" would therefore make the output depend on
     * core count.
     *
     * So the winner is chosen by an explicit rule instead: the longer trace,
     * because it explains more, and on a tie the lexicographically smaller one,
     * because it has to be *something* and that something has to be total.
     */
    private function normalised(): self
    {
        $unique = [];

        foreach ($this->findings as $finding) {
            $key = implode("\0", [
                $finding->ruleId,
                $finding->file,
                (string) $finding->line,
                (string) $finding->column,
                $finding->kind->value,
                $finding->fingerprint,
            ]);

            $existing = $unique[$key] ?? null;

            if ($existing === null || self::preferredOf($existing, $finding) === $finding) {
                $unique[$key] = $finding;
            }
        }

        $findings = array_values($unique);
        usort($findings, static fn (Finding $a, Finding $b): int => $a->compareTo($b));

        return new self($findings);
    }

    private static function preferredOf(Finding $a, Finding $b): Finding
    {
        if (count($a->trace) !== count($b->trace)) {
            return count($a->trace) > count($b->trace) ? $a : $b;
        }

        return self::traceSignature($a) <= self::traceSignature($b) ? $a : $b;
    }

    private static function traceSignature(Finding $finding): string
    {
        $parts = [];

        foreach ($finding->trace as $step) {
            $parts[] = implode(':', [
                $step->verb->value,
                $step->file,
                (string) $step->line,
                (string) $step->column,
                $step->description,
            ]);
        }

        return implode("\0", $parts);
    }
}
