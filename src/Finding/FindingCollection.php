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
     * @param array<string, list<string>> $precedence superseded rule id => rule
     *                                                ids that supersede it; an
     *                                                empty list means any other
     *                                                rule supersedes it
     */
    public function withRulePrecedence(array $precedence): self
    {
        $anchors = [];

        foreach ($this->findings as $finding) {
            $anchors[$finding->file . ':' . $finding->line . ':' . $finding->kind->value][$finding->ruleId] = true;
        }

        return $this->filter(static function (Finding $finding) use ($precedence, $anchors): bool {
            $supersededBy = $precedence[$finding->ruleId] ?? null;

            if ($supersededBy === null) {
                return true;
            }

            $atLocation = $anchors[$finding->file . ':' . $finding->line . ':' . $finding->kind->value] ?? [];
            unset($atLocation[$finding->ruleId]);

            if ($supersededBy === []) {
                return $atLocation === [];
            }

            foreach ($supersededBy as $ruleId) {
                if (isset($atLocation[$ruleId])) {
                    return false;
                }
            }

            return true;
        });
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

            // Keep the first occurrence: passes run in a fixed order, and the
            // earlier pass is the one with the more complete trace.
            $unique[$key] ??= $finding;
        }

        $findings = array_values($unique);
        usort($findings, static fn (Finding $a, Finding $b): int => $a->compareTo($b));

        return new self($findings);
    }
}
