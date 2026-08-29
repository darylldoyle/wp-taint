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

    private ?ProgressBar $bar = null;

    private string $label = '';

    private int $done = 0;

    public function __construct(private readonly OutputInterface $output)
    {
    }

    public function phase(string $label, ?int $total = null): void
    {
        $this->clear();

        $this->label = $label;
        $this->done = 0;

        if ($total === null || $total === 0) {
            // No total: say what is happening and leave it on screen. A bar
            // that cannot fill is worse than a sentence.
            $this->output->write(sprintf("\r\033[K  %s…", $label));

            return;
        }

        $this->bar = new ProgressBar($this->output, $total);
        $this->bar->setFormat('  %message% %current%/%max% [%bar%] %percent:3s%%');
        $this->bar->setMessage($label);
        $this->bar->setBarCharacter('=');
        $this->bar->setProgressCharacter('>');
        $this->bar->setEmptyBarCharacter(' ');
        $this->bar->setRedrawFrequency(self::REDRAW_EVERY);
        $this->bar->start();
    }

    public function advance(int $steps = 1): void
    {
        $this->done += $steps;

        if ($this->bar !== null) {
            $this->bar->advance($steps);

            return;
        }

        // An uncounted phase still has something to report. The fixed point
        // knows which round it is on, and "round 7" moving is the difference
        // between working and hung.
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
        }

        $this->output->write("\r\033[K");
    }
}
