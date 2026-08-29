<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Scan\ScanProgress;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A progress bar on stderr while a scan runs.
 *
 * Everything goes to stderr so that `-o -`, a piped SARIF report and a shell
 * redirect all still produce exactly the bytes they produced before.
 *
 * ## Why it is only sometimes shown
 *
 * A bar redraws with carriage returns, which turn into thousands of lines of
 * noise in a file or a CI log. It is rendered only when stderr is a terminal
 * that has told us it can handle decoration.
 */
final class ConsoleScanProgress implements ScanProgress
{
    /**
     * How often to redraw a counted phase.
     *
     * Parsing thousands of small files is fast enough that redrawing on each
     * one costs more than the parse does.
     */
    private const REDRAW_EVERY = 25;

    /**
     * How long a scan runs before anything is drawn.
     *
     * A small scan finishes before a bar could be read, and flashing one up for
     * 80ms is worse than staying quiet. Counting files instead was the first
     * attempt and it measured the wrong thing: the count is not known until
     * after the directory walk, which is itself the part that felt like a hang
     * on a big tree.
     */
    private const QUIET_FOR_MS = 250;

    private ?ProgressBar $bar = null;

    private string $label = '';

    private int $done = 0;

    private ?int $total = null;

    /** Whether anything has been written that needs erasing. */
    private bool $drawn = false;

    private readonly float $startedAt;

    public function __construct(private readonly OutputInterface $output)
    {
        $this->startedAt = microtime(true);
    }

    public function phase(string $label, ?int $total = null): void
    {
        $this->clear();

        $this->label = $label;
        $this->total = $total;
        $this->done = 0;

        if (! $this->awake()) {
            return;
        }

        $this->render();
    }

    /**
     * Has the scan been running long enough to be worth reporting on?
     */
    private function awake(): bool
    {
        return (microtime(true) - $this->startedAt) * 1000 >= self::QUIET_FOR_MS;
    }

    /**
     * Draw the current phase from scratch.
     *
     * Separate from {@see phase} because a phase that begins before the quiet
     * period is over still has to appear once it ends, part-way through.
     */
    private function render(): void
    {
        $total = $this->total;

        if ($total === null || $total === 0) {
            // No total: say what is happening and leave it on screen. A bar
            // that cannot fill is worse than a sentence.
            $this->drawn = true;
            $this->output->write(sprintf("\r\033[K  %s…", $this->label));

            return;
        }

        $this->bar = new ProgressBar($this->output, $total);
        $this->bar->setFormat('  %message% %current%/%max% [%bar%] %percent:3s%%');
        $this->bar->setMessage($this->label);
        $this->bar->setBarCharacter('=');
        $this->bar->setProgressCharacter('>');
        $this->bar->setEmptyBarCharacter(' ');
        $this->bar->setRedrawFrequency(self::REDRAW_EVERY);
        $this->bar->start($total);
        $this->bar->setProgress($this->done);
    }

    public function advance(int $steps = 1): void
    {
        $this->done += $steps;

        if (! $this->awake()) {
            return;
        }

        // The quiet period ended part-way through this phase, so draw it now
        // with the progress it has actually made.
        if ($this->bar === null && $this->total !== null && $this->total !== 0) {
            $this->render();

            return;
        }

        if ($this->bar !== null) {
            $this->bar->advance($steps);

            return;
        }

        // An uncounted phase still has something to report. The fixed point
        // knows which round it is on, and "round 7" moving is the difference
        // between working and hung.
        $this->drawn = true;
        $this->output->write(sprintf("\r\033[K  %s… round %d", $this->label, $this->done));
    }

    public function finish(): void
    {
        $this->clear();
    }

    private function clear(): void
    {
        if ($this->bar !== null) {
            $this->bar->finish();
            $this->bar->clear();
            $this->bar = null;
            $this->drawn = false;
            $this->output->write("\r\033[K");

            return;
        }

        // Nothing was drawn, so there is nothing to erase. Writing the erase
        // sequence anyway put a run of `[K` in front of the report whenever the
        // scan finished inside the quiet period.
        if ($this->drawn) {
            $this->drawn = false;
            $this->output->write("\r\033[K");
        }
    }
}
