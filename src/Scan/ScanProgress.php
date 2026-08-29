<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

/**
 * Somewhere for a long scan to say what it is doing.
 *
 * A scan of a real WordPress tree spends most of its time in two places —
 * parsing, and the interprocedural fixed point — and said nothing during
 * either. On a client theme that is fifteen seconds of silence; with reference
 * trees it was seven and a half minutes, which reads as a hang.
 *
 * The scanner reports phases; what to do with them is the caller's business.
 * {@see NullScanProgress} is the default, so nothing in the analysis path has to
 * know whether anyone is watching.
 */
interface ScanProgress
{
    /**
     * Begin a phase.
     *
     * @param int|null $total how many steps it has, or null when the phase
     *                        cannot say — the fixed point does not know how
     *                        many rounds it needs until it stops needing them
     */
    public function phase(string $label, ?int $total = null): void;

    /**
     * One step of the current phase is done.
     */
    public function advance(int $steps = 1): void;

    /**
     * Every phase is finished; take the display down.
     */
    public function finish(): void;
}
