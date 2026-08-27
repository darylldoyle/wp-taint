<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Block;
use PHPCfg\Op;
use SplObjectStorage;

/**
 * Every block of a function body, in a deterministic order.
 *
 * Depth-first from the entry block, following each op's sub-blocks in
 * declaration order. Same input, same order, every run — which is what makes
 * the output byte-identical.
 */
final class BlockOrder
{
    /**
     * @return list<Block>
     */
    public static function of(?Block $entry): array
    {
        if ($entry === null) {
            return [];
        }

        /** @var SplObjectStorage<Block, true> $seen */
        $seen = new SplObjectStorage();
        $ordered = [];

        self::visit($entry, $seen, $ordered);

        return $ordered;
    }

    /**
     * @param SplObjectStorage<Block, true> $seen
     * @param list<Block>                   $ordered
     */
    private static function visit(Block $block, SplObjectStorage $seen, array &$ordered): void
    {
        if ($seen->contains($block)) {
            return;
        }

        $seen->attach($block);
        $ordered[] = $block;

        foreach ($block->children as $op) {
            if (! $op instanceof Op) {
                continue;
            }

            foreach ($op->getSubBlocks() as $sub) {
                foreach (is_array($sub) ? $sub : [$sub] as $target) {
                    if ($target instanceof Block) {
                        self::visit($target, $seen, $ordered);
                    }
                }
            }
        }
    }
}
