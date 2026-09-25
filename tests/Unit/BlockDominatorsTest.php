<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Taint\BlockDominators;
use Enshrined\WpTaint\Taint\BlockOrder;

/**
 * @return list<PHPCfg\Block>
 */
function blocksOf(string $source): array
{
    $file = tempnam(sys_get_temp_dir(), 'wp-taint-dom') . '.php';
    file_put_contents($file, $source);

    try {
        $script = (new CfgBuilder(dirname($file)))->buildFromFile($file)->file()->script;
    } finally {
        unlink($file);
    }

    $func = array_values($script->functions)[0];

    return BlockOrder::of($func->cfg);
}

it('finds the blocks every path passes through', function (): void {
    $blocks = blocksOf('<?php function f( $a ) { if ( $a ) { echo 1; } else { echo 2; } echo 3; }');
    $dominators = BlockDominators::compute($blocks);

    expect($dominators)->not->toBeNull();

    foreach ($blocks as $block) {
        $of = iterator_to_array($dominators->of($block), false);

        // The entry dominates everything, and every block dominates itself.
        expect($of)->toContain($blocks[0]);
        expect($of)->toContain($block);
    }

    // Neither arm of the if dominates the block after it.
    $join = $blocks[count($blocks) - 1];
    $of = iterator_to_array($dominators->of($join), false);

    expect(count($of))->toBeLessThan(count($blocks));
});

it('handles a function of thousands of blocks in little memory', function (): void {
    // Each if adds blocks, and every join is dominated by every join before
    // it. Held as object sets, the starting point alone was n² entries: about
    // 80 million here, and gigabytes.
    $body = '';

    for ($i = 0; $i < 3000; $i++) {
        $body .= "if ( \$a == $i ) { echo $i; }\n";
    }

    $blocks = blocksOf("<?php function f( \$a ) {\n$body}");
    expect(count($blocks))->toBeGreaterThan(6000);

    $before = memory_get_usage();
    $dominators = BlockDominators::compute($blocks);
    $used = memory_get_usage() - $before;

    expect($used)->toBeLessThan(64 * 1024 * 1024);

    $last = $blocks[count($blocks) - 1];
    $of = iterator_to_array($dominators->of($last), false);

    expect($of)->toContain($blocks[0]);
    expect($of)->toContain($last);
});

it('answers the same list from memory, and a new list afresh', function (): void {
    $blocks = blocksOf('<?php function f( $a ) { if ( $a ) { echo 1; } echo 2; }');
    $other = blocksOf('<?php function g( $b ) { while ( $b ) { $b--; } }');

    $first = BlockDominators::compute($blocks);

    expect(BlockDominators::compute($blocks))->toBe($first);
    expect(BlockDominators::compute($other))->not->toBe($first);
    expect(BlockDominators::compute([]))->toBeNull();
});
