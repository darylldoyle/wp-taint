<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Scan\ScanProgress;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * One line per phase, and per fixed-point round: heap in use, the peak so far,
 * and how long it took.
 *
 * `--debug-memory`. The operating system's view of a large scan is no use for
 * this: macOS compresses and swaps the process, so its resident size fell to a
 * few hundred megabytes while PHP held eleven gigabytes. PHP's own accounting
 * is the number that says which phase to look at.
 *
 * Plain lines, never a redrawn bar, so the output survives a pipe or a log.
 */
final class MemoryScanProgress implements ScanProgress
{
    private ?string $label = null;

    private int $round = 0;

    private int $startedAt;

    private int $phaseStartedAt;

    /** Seconds the cycle collector had spent when this phase or round began. */
    private float $collectedAtPhaseStart;

    public function __construct(private readonly OutputInterface $output)
    {
        $this->startedAt = $this->phaseStartedAt = self::now();
        $this->collectedAtPhaseStart = self::collectorSeconds();
    }

    public function phase(string $label, ?int $total = null): void
    {
        $this->report();
        $this->label = $label;
        $this->round = 0;
        $this->phaseStartedAt = self::now();
    }

    public function advance(int $steps = 1): void
    {
        // The fixed point is the only phase with no total, and each advance is
        // a round. Rounds are where memory and time go, so each gets a line.
        if ($this->label !== 'Resolving taint across functions') {
            return;
        }

        if ($this->round > 0) {
            $this->report(sprintf('round %d', $this->round));
            $this->phaseStartedAt = self::now();
        }

        $this->round += $steps;
    }

    public function note(string $message): void
    {
        $this->output->writeln('[memory] ' . $message);
    }

    public function finish(): void
    {
        $this->report($this->round > 0 ? sprintf('round %d', $this->round) : null);
        $this->label = null;
        $this->output->writeln(sprintf(
            '[memory] total %.1fs, peak %s',
            (self::now() - $this->startedAt) / 1e9,
            self::megabytes(memory_get_peak_usage()),
        ));
    }

    private function report(?string $detail = null): void
    {
        if ($this->label === null) {
            return;
        }

        $collected = self::collectorSeconds();

        $this->output->writeln(sprintf(
            '[memory] %-40s %8.1fs  heap %9s  peak %9s  gc %7.1fs',
            $this->label . ($detail === null ? '' : ', ' . $detail),
            (self::now() - $this->phaseStartedAt) / 1e9,
            self::megabytes(memory_get_usage()),
            self::megabytes(memory_get_peak_usage()),
            $collected - $this->collectedAtPhaseStart,
        ));
        $this->collectedAtPhaseStart = $collected;
    }

    /**
     * Nanoseconds. `hrtime(true)` is typed int|float because a 32-bit build
     * overflows into a float; this is a 64-bit tool.
     */
    private static function now(): int
    {
        return (int) hrtime(true);
    }

    /**
     * Time PHP has spent collecting cycles, which a large scan can lose most of
     * its time to. PHP 8.3 reports it; earlier versions read as zero.
     */
    private static function collectorSeconds(): float
    {
        // PHPStan checks against PHP 8.2, the oldest supported, which has no
        // timings in gc_status().
        return gc_status()['collector_time'] ?? 0.0; // @phpstan-ignore nullCoalesce.offset
    }

    private static function megabytes(int $bytes): string
    {
        return number_format($bytes / 1_048_576) . 'MB';
    }
}
