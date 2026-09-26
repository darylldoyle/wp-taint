<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\GraphDisposer;
use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Taint\BlockOrder;
use PHPCfg\Operand;

/**
 * A weak reference to every block, op and operand the analysis walks.
 *
 * @return list<WeakReference<object>>
 */
function weakGraph(ParsedFile $file): array
{
    $weak = [];

    foreach ([$file->script->main, ...array_values($file->script->functions)] as $func) {
        foreach (BlockOrder::of($func->cfg) as $block) {
            $weak[] = WeakReference::create($block);

            foreach ([...$block->phi, ...$block->children] as $op) {
                $weak[] = WeakReference::create($op);

                foreach ($op->getVariableNames() as $name) {
                    $value = $op->$name;

                    foreach (is_array($value) ? $value : [$value] as $operand) {
                        if ($operand instanceof Operand) {
                            $weak[] = WeakReference::create($operand);
                        }
                    }
                }
            }
        }
    }

    return $weak;
}

/**
 * @param list<WeakReference<object>> $weak
 */
function stillAlive(array $weak): int
{
    return count(array_filter($weak, static fn (WeakReference $reference): bool => $reference->get() !== null));
}

it('frees almost all of a disposed graph without the cycle collector, and all of it with one', function (): void {
    // A real, large file: one of the engine's own classes, with loops, try,
    // match and closures.
    $path = dirname(__DIR__, 2) . '/src/Taint/CallResolver.php';
    $file = (new CfgBuilder(dirname($path)))->buildFromFile($path)->file();
    $file->releaseAst();
    $weak = weakGraph($file);
    $wasEnabled = gc_enabled();
    gc_disable();

    try {
        GraphDisposer::dispose($file);
        unset($file);

        // Measured at 7 of 3,131. A handful stay reachable from a cycle the
        // disposer does not reach, so they wait for a collection. What
        // matters is that almost nothing does, and that nothing leaks.
        expect(stillAlive($weak))->toBeLessThan(intdiv(count($weak), 100));

        gc_collect_cycles();

        expect(stillAlive($weak))->toBe(0);
    } finally {
        if ($wasEnabled) {
            gc_enable();
        }
    }
});

it('leaves a graph standing until it is disposed', function (): void {
    $path = dirname(__DIR__) . '/Fixtures/vulnerable/sqli-wpdb-query-interpolation.php';
    $file = (new CfgBuilder(dirname($path)))->buildFromFile($path)->file();
    $weak = weakGraph($file);
    $wasEnabled = gc_enabled();
    gc_disable();

    try {
        unset($file);

        // Without the disposer the graph is cyclic garbage: it outlives its
        // last reference until a collection finds it.
        expect(stillAlive($weak))->toBeGreaterThan(0);
    } finally {
        gc_collect_cycles();

        if ($wasEnabled) {
            gc_enable();
        }
    }
});
