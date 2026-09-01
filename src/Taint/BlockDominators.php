<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Block;
use SplObjectStorage;

/**
 * Which blocks every path to each block must pass through.
 *
 * Extracted from {@see GuardAnalyzer} unchanged when {@see CapabilityGuard}
 * arrived asking the same question with a different predicate. Both suppress
 * findings and nothing else, so both need the strong form: a guard counts only
 * when there is genuinely no way around it.
 */
final class BlockDominators
{
    /** Dominance settles in a handful of rounds; this is a runaway backstop. */
    private const MAX_ROUNDS = 32;

    /**
     * The textbook iterative formulation: a block is dominated by itself and by
     * everything that dominates all of its predecessors. Started pessimistically
     * with every block dominating every block, and narrowed until it settles.
     *
     * @param list<Block> $blocks
     *
     * @return SplObjectStorage<Block, SplObjectStorage<Block, true>>
     */
    public static function compute(array $blocks): SplObjectStorage
    {
        $entry = $blocks[0] ?? null;

        /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>> $empty */
        $empty = new SplObjectStorage();

        if ($entry === null) {
            return $empty;
        }

        /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>> $dominators */
        $dominators = new SplObjectStorage();

        foreach ($blocks as $block) {
            /** @var SplObjectStorage<Block, true> $all */
            $all = new SplObjectStorage();

            foreach ($blocks as $other) {
                $all->attach($other, true);
            }

            $dominators->attach($block, $all);
        }

        /** @var SplObjectStorage<Block, true> $entryOnly */
        $entryOnly = new SplObjectStorage();
        $entryOnly->attach($entry, true);
        $dominators[$entry] = $entryOnly;

        for ($round = 0; $round < self::MAX_ROUNDS; $round++) {
            $changed = false;

            foreach ($blocks as $block) {
                if ($block === $entry) {
                    continue;
                }

                $intersection = null;

                foreach ($block->parents as $parent) {
                    if (! $dominators->contains($parent)) {
                        continue;
                    }

                    /** @var SplObjectStorage<Block, true> $parentDominators */
                    $parentDominators = $dominators[$parent];

                    if ($intersection === null) {
                        /** @var SplObjectStorage<Block, true> $intersection */
                        $intersection = clone $parentDominators;

                        continue;
                    }

                    // SplObjectStorage's intersection is removeAllExcept().
                    $intersection->removeAllExcept($parentDominators);
                }

                /** @var SplObjectStorage<Block, true> $next */
                $next = $intersection ?? new SplObjectStorage();
                $next->attach($block, true);

                /** @var SplObjectStorage<Block, true> $current */
                $current = $dominators[$block];

                if (count($next) !== count($current)) {
                    $dominators[$block] = $next;
                    $changed = true;
                }
            }

            if (! $changed) {
                break;
            }
        }

        return $dominators;
    }
}
