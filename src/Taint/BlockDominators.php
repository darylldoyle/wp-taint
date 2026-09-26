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
 *
 * ## Bit words, not object sets
 *
 * Each block's dominators are a bit set indexed by the block's position in the
 * list. They were object sets, and the algorithm starts with every block
 * dominating every block, so a function of n blocks began with n² entries. A
 * generated file in one site's 168 reference trees had a function big
 * enough to need several gigabytes for that alone, and the scan died there at
 * both an 8GB and a 12GB limit. As bits, n² costs n²/8 bytes. The iteration is
 * the same: the same order, the same test on each set's size, the same round
 * cap. A check over every function in woocommerce and jetpack found every set
 * identical to the object form's.
 *
 * The sets are read through {@see of()} rather than handed out, because a
 * long chain of blocks gives the last block a set nearly as large as the
 * function, and building every set as objects would bring the n² back.
 */
final class BlockDominators
{
    /** Dominance settles in a handful of rounds; this is a runaway backstop. */
    private const MAX_ROUNDS = 32;

    /** Bits per word. PHP's integers are 64-bit. */
    private const WORD = 64;

    /**
     * The last answer. The same block list is asked about four times in a
     * row: by {@see GuardAnalyzer} and {@see CapabilityGuard}, in the summary
     * pass and again in the property pass. On a 40-tree scan that was 1.2
     * million computations and an eighth of the fixed point's time. It holds
     * its block list, so the identity check in {@see compute()} cannot match a
     * different list whose blocks reuse the same objects' memory.
     */
    private static ?self $last = null;

    /** @var array<int, int> how many bits each 16-bit value has set */
    private static array $bitsIn = [];

    /**
     * @param list<Block>              $blocks
     * @param SplObjectStorage<Block, int> $position each block's index in $blocks
     * @param array<int, array<int, int>> $sets each block's dominators, as bit words
     */
    private function __construct(
        private readonly array $blocks,
        private readonly SplObjectStorage $position,
        private readonly array $sets,
    ) {
    }

    /**
     * The textbook iterative formulation: a block is dominated by itself and by
     * everything that dominates all of its predecessors. Started pessimistically
     * with every block dominating every block, and narrowed until it settles.
     *
     * @param list<Block> $blocks the function's blocks, entry first
     */
    public static function compute(array $blocks): ?self
    {
        if ($blocks === []) {
            return null;
        }

        if (self::$last !== null && self::$last->blocks === $blocks) {
            return self::$last;
        }

        /** @var SplObjectStorage<Block, int> $position */
        $position = new SplObjectStorage();

        foreach ($blocks as $index => $block) {
            $position[$block] = $index;
        }

        return self::$last = new self($blocks, $position, self::sets($blocks, $position));
    }

    /**
     * Whether this block is one of the function's.
     */
    public function covers(Block $block): bool
    {
        return $this->position->contains($block);
    }

    /**
     * Every block that dominates this one, itself included, in list order.
     *
     * @return iterable<Block>
     */
    public function of(Block $block): iterable
    {
        if (! $this->position->contains($block)) {
            return;
        }

        foreach ($this->sets[$this->position[$block]] ?? [] as $word => $bits) {
            while ($bits !== 0) {
                // The lowest set bit, then clear it. The top bit alone is
                // PHP_INT_MIN, whose negation overflows, so it is taken as is.
                $lowest = $bits === PHP_INT_MIN ? PHP_INT_MIN : $bits & -$bits;
                $bits ^= $lowest;

                $dominator = $this->blocks[$word * self::WORD + self::bitIndex($lowest)] ?? null;

                if ($dominator !== null) {
                    yield $dominator;
                }
            }
        }
    }

    /**
     * @param list<Block>                  $blocks
     * @param SplObjectStorage<Block, int> $position
     *
     * @return array<int, array<int, int>>
     */
    private static function sets(array $blocks, SplObjectStorage $position): array
    {
        $count = count($blocks);
        $words = intdiv($count + self::WORD - 1, self::WORD);

        // Every block, as bit words: all ones, except the unused top of the
        // last word.
        $all = array_fill(0, $words, -1);
        $used = $count - ($words - 1) * self::WORD;

        if ($used < self::WORD) {
            // Bits 0 to $used - 1. With 63 of them, the shift would reach the
            // sign bit and the subtraction would overflow to a float.
            $all[$words - 1] = $used === self::WORD - 1 ? PHP_INT_MAX : (1 << $used) - 1;
        }

        $sets = array_fill(0, $count, $all);
        $sizes = array_fill(0, $count, $count);

        $entryOnly = array_fill(0, $words, 0);
        $entryOnly[0] = 1;
        $sets[0] = $entryOnly;
        $sizes[0] = 1;

        for ($round = 0; $round < self::MAX_ROUNDS; $round++) {
            $changed = false;

            foreach ($blocks as $index => $block) {
                if ($index === 0) {
                    continue;
                }

                $intersection = null;

                foreach ($block->parents as $parent) {
                    if (! $position->contains($parent)) {
                        continue;
                    }

                    $parentSet = $sets[$position[$parent]] ?? [];

                    if ($intersection === null) {
                        $intersection = $parentSet;

                        continue;
                    }

                    for ($word = 0; $word < $words; $word++) {
                        $intersection[$word] = ($intersection[$word] ?? 0) & ($parentSet[$word] ?? 0);
                    }
                }

                $next = $intersection ?? array_fill(0, $words, 0);
                $offset = $index % self::WORD;
                $word = intdiv($index, self::WORD);
                $next[$word] = ($next[$word] ?? 0) | ($offset === self::WORD - 1 ? PHP_INT_MIN : 1 << $offset);

                $size = self::size($next);

                if ($size !== ($sizes[$index] ?? -1)) {
                    $sets[$index] = $next;
                    $sizes[$index] = $size;
                    $changed = true;
                }
            }

            if (! $changed) {
                break;
            }
        }

        return $sets;
    }

    /**
     * @param array<int, int> $set
     */
    private static function size(array $set): int
    {
        if (self::$bitsIn === []) {
            self::$bitsIn[0] = 0;

            for ($value = 1; $value < 65536; $value++) {
                self::$bitsIn[$value] = (self::$bitsIn[$value >> 1] ?? 0) + ($value & 1);
            }
        }

        $size = 0;

        foreach ($set as $bits) {
            $size += (self::$bitsIn[$bits & 0xFFFF] ?? 0)
                + (self::$bitsIn[($bits >> 16) & 0xFFFF] ?? 0)
                + (self::$bitsIn[($bits >> 32) & 0xFFFF] ?? 0)
                + (self::$bitsIn[($bits >> 48) & 0xFFFF] ?? 0);
        }

        return $size;
    }

    /**
     * The position of the one bit set in a word.
     */
    private static function bitIndex(int $bit): int
    {
        if ($bit === PHP_INT_MIN) {
            return self::WORD - 1;
        }

        $index = 0;

        while ($bit > 1) {
            $bit >>= 1;
            $index++;
        }

        return $index;
    }
}
