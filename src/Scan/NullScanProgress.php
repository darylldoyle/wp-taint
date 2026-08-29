<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

/**
 * The default: nobody is watching.
 *
 * A scan run from a test, a tool or a pipe has no use for a progress bar, and
 * making the scanner ask whether it has one would put that question in every
 * phase boundary.
 */
final class NullScanProgress implements ScanProgress
{
    public function phase(string $label, ?int $total = null): void
    {
    }

    public function advance(int $steps = 1): void
    {
    }

    public function finish(): void
    {
    }
}
