<?php

/**
 * Checks that {@see \Enshrined\WpTaint\Cfg\Simplifier} builds exactly the graphs
 * php-cfg's own simplifier builds.
 *
 * Every file is built twice, printed with php-cfg's text printer, and the two
 * printouts compared. Any difference is listed and the exit status is 1. Run it
 * over the corpus before changing the simplifier; a faster graph that is a
 * different graph is a different analysis.
 *
 * On the 50 corpus plugins, 24,798 files, the last run reported 6 files as
 * different. All six differ only in the order of a phi's operands and the
 * variable numbering that follows from it; a phi's taint is the union of its
 * operands, so the order carries no meaning. A new difference of any other
 * kind needs reading before the simplifier changes.
 *
 * Usage:
 *   php tools/compare-simplifier.php <path>...
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Taint\OperandHelper;
use PHPCfg\Printer\Text;

$paths = array_slice($argv, 1);

if ($paths === []) {
    fwrite(STDERR, "Usage: php tools/compare-simplifier.php <path>...\n");

    exit(2);
}

$ours = new CfgBuilder('/');
$upstream = new CfgBuilder('/', upstreamSimplifier: true);
$files = (new FileFinder([], false))->find($paths);
$compared = 0;
$unprintable = 0;
$explained = 0;
$different = [];
$oursSeconds = 0.0;
$upstreamSeconds = 0.0;

foreach ($files as $index => $file) {
    $start = hrtime(true);
    $a = $ours->buildFromFile($file);
    $oursSeconds += (hrtime(true) - $start) / 1e9;

    $start = hrtime(true);
    $b = $upstream->buildFromFile($file);
    $upstreamSeconds += (hrtime(true) - $start) / 1e9;

    if ($a->isSuccess() !== $b->isSuccess()) {
        $different[] = $file . ' (parsed by one simplifier only)';

        continue;
    }

    if (! $a->isSuccess()) {
        continue;
    }

    $compared++;

    $printedA = printed($a->file()->script);
    $printedB = printed($b->file()->script);

    // php-cfg's printer throws on some catch/finally shapes whichever
    // simplifier built the graph. Both failing the same way is not a
    // difference, but it is not a comparison either, so it is counted.
    if (str_starts_with($printedA, 'unprintable:') && $printedA === $printedB) {
        $unprintable++;
    } elseif ($printedA !== $printedB) {
        // Upstream's replaceVariables() walks only the blocks reachable from
        // the removed phi's block, through getSubBlocks(), so a use behind a
        // catch or finally edge can keep pointing at a phi that no longer
        // exists. Ours replaces every use. That difference is upstream's bug,
        // and it is only acceptable as the explanation when ours has fewer of
        // them. Not necessarily none: php-cfg's jump threading in enterOp(),
        // which is upstream's code unchanged, leaves some of its own.
        $danglingOurs = danglingPhiReferences($a->file()->script);
        $danglingUpstream = danglingPhiReferences($b->file()->script);

        if ($danglingOurs < $danglingUpstream) {
            $explained++;
        } else {
            $different[] = sprintf(
                '%s (dangling phi references: ours %d, upstream %d)',
                $file,
                $danglingOurs,
                $danglingUpstream,
            );
        }
    }

    if ($index % 2000 === 1999) {
        fprintf(STDERR, "  %d/%d files, %d different\n", $index + 1, count($files), count($different));
    }
}

printf(
    "%d files compared, %d different, %d differ only by ours leaving fewer references to a removed phi, "
        . "%d unprintable by php-cfg with either simplifier. Build time: ours %.1fs, upstream %.1fs.\n",
    $compared,
    count($different),
    $explained,
    $unprintable,
    $oursSeconds,
    $upstreamSeconds,
);

foreach ($different as $file) {
    echo '  ', $file, "\n";
}

exit($different === [] ? 0 : 1);

/**
 * A fresh printer every time. php-cfg's text printer keeps object-keyed state
 * between calls, and PHP reuses an object's id once it is freed, so a printer
 * shared across files names operands after objects from an earlier file: in a
 * long run, upstream compared against itself reported 16 differences in one
 * plugin.
 */
function printed(PHPCfg\Script $script): string
{
    try {
        $printed = (new Text())->printScript($script);

        return is_string($printed) ? $printed : 'unprintable: printer returned ' . get_debug_type($printed);
    } catch (Throwable $error) {
        return 'unprintable: ' . $error::class . ': ' . $error->getMessage();
    }
}

/**
 * Operands read by a live op whose only writers are phis no longer in any live
 * block: references to a removed phi.
 */
function danglingPhiReferences(PHPCfg\Script $script): int
{
    $count = 0;

    foreach ([$script->main, ...$script->functions] as $func) {
        if (! $func instanceof PHPCfg\Func || ! $func->cfg instanceof PHPCfg\Block) {
            continue;
        }

        $live = liveOps($func->cfg);

        foreach ($live as $op) {
            foreach (OperandHelper::operandsOf($op) as $operand) {
                if ($operand->ops !== [] && writtenOnlyByRemovedPhis($operand, $live)) {
                    $count++;
                }
            }
        }
    }

    return $count;
}

/**
 * @param SplObjectStorage<PHPCfg\Op, null> $live
 */
function writtenOnlyByRemovedPhis(PHPCfg\Operand $operand, SplObjectStorage $live): bool
{
    foreach ($operand->ops as $writer) {
        if (! $writer instanceof PHPCfg\Op\Phi || $live->contains($writer)) {
            return false;
        }
    }

    return true;
}

/**
 * Every op in a block reachable from the entry, through sub-blocks and through
 * catch and finally targets.
 *
 * @return SplObjectStorage<PHPCfg\Op, null>
 */
function liveOps(PHPCfg\Block $entry): SplObjectStorage
{
    /** @var SplObjectStorage<PHPCfg\Op, null> $live */
    $live = new SplObjectStorage();

    /** @var SplObjectStorage<PHPCfg\Block, null> $visited */
    $visited = new SplObjectStorage();
    $pending = [$entry];

    while ($pending !== []) {
        $block = array_pop($pending);

        if ($visited->contains($block)) {
            continue;
        }

        $visited->attach($block);

        /** @var list<PHPCfg\Op> $ops */
        $ops = [...$block->phi, ...$block->children];

        foreach ($ops as $op) {
            $live->attach($op);

            foreach ($op->getSubBlocks() as $subBlocks) {
                foreach (is_array($subBlocks) ? $subBlocks : [$subBlocks] as $sub) {
                    if ($sub instanceof PHPCfg\Block) {
                        $pending[] = $sub;
                    }
                }
            }
        }

        $catchTarget = $block->catchTarget;

        if (! is_object($catchTarget)) {
            continue;
        }

        /** @var list<array{block: mixed}> $catches */
        $catches = $catchTarget->catches;

        foreach ($catches as $catch) {
            if ($catch['block'] instanceof PHPCfg\Block) {
                $pending[] = $catch['block'];
            }
        }

        $finally = $catchTarget->finally ?? null;

        if ($finally instanceof PHPCfg\Block) {
            $pending[] = $finally;
        }
    }

    return $live;
}
