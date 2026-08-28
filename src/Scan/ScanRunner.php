<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cli\ScanConfiguration;

/**
 * Builds a {@see Scanner} from the resolved configuration and runs it.
 *
 * ## There was a result cache here
 *
 * It stored whole scan results keyed on the tool version, the resolved
 * catalogue and the content of every file. Whole-scan rather than per-file,
 * because interprocedural taint crosses files and caching one file's findings
 * would be wrong the moment a function it calls changed elsewhere.
 *
 * It was removed, for one reason and one aggravation.
 *
 * **The key covered catalogue names, not catalogue contents.** It hashed
 * `array_keys($registry->sanitizers())`, so editing a custom registry — turning
 * `clears = ["sql"]` into `clears = ["html"]`, changing a sink's severity —
 * left the key identical and served the previous answer. Anyone tuning their
 * own catalogue would have concluded their edits did nothing. In a security
 * scanner a stale clean result is the same as lying, and a cache that can do
 * that is worth less than the time it saves.
 *
 * The aggravation: during development the key includes the tool version, which
 * does not move between commits, so a fixed engine kept returning the broken
 * answer until someone thought to pass `--no-cache`. That cost real time twice
 * in one afternoon.
 *
 * What it bought was a re-scan of unchanged code — 15.6s to 0.18s on Duplicator.
 * Worth having, and worth having correctly: the way back is to hash the
 * resolved catalogue itself rather than its keys.
 */
final class ScanRunner
{
    public function __construct(private readonly ScanConfiguration $configuration)
    {
    }

    /**
     * @param list<string> $files
     */
    public function run(array $files): ScanResult
    {
        return (new Scanner(
            $this->configuration->registry,
            $this->configuration->analysis,
            $this->configuration->root,
            $this->configuration->structuralRules,
            $this->configuration->dumpTaintGraph,
            $this->configuration->jobs,
            $this->configuration->includePaths,
        ))->scan($files);
    }
}
