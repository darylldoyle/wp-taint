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
     * The block list the last answer was computed for. Held, so its blocks
     * stay alive and the identity check in {@see compute()} cannot match a
     * different list whose blocks reused the same objects' memory.
     *
     * @var list<Block>
     */
    private static array $lastBlocks = [];

    /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>>|null */
    private static ?SplObjectStorage $lastAnswer = null;

    /**
     * Each block's dominators, remembered for the last block list asked about.
     *
     * The same list is asked about four times in a row: by
     * {@see GuardAnalyzer} and {@see CapabilityGuard}, in the summary pass and
     * again in the property pass. On a 40-tree scan that was 1.2 million
     * computations and a ninth of the fixed point's time. The answer is copied
     * for each caller, because callers iterate it and a shared iterator would
     * move under one caller while another walks it.
     *
     * @param list<Block> $blocks
     *
     * @return SplObjectStorage<Block, SplObjectStorage<Block, true>>
     */
    public static function compute(array $blocks): SplObjectStorage
    {
        if (self::$lastAnswer === null || $blocks !== self::$lastBlocks) {
            self::$lastAnswer = self::computeFresh($blocks);
            self::$lastBlocks = $blocks;
        }

        /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>> $copy */
        $copy = new SplObjectStorage();

        foreach (self::$lastAnswer as $block) {
            $copy->attach($block, clone self::$lastAnswer[$block]);
        }

        return $copy;
    }

    /**
     * The textbook iterative formulation: a block is dominated by itself and by
     * everything that dominates all of its predecessors. Started pessimistically
     * with every block dominating every block, and narrowed until it settles.
     *
     * @param list<Block> $blocks
     *
     * @return SplObjectStorage<Block, SplObjectStorage<Block, true>>
     */
    private static function computeFresh(array $blocks): SplObjectStorage
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
