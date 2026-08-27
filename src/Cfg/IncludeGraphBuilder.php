<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\FunctionContext;
use PHPCfg\Op;

/**
 * Resolves every `include` and `require` site in the scan, once.
 *
 * Before analysis, like the hook graph and for the same reason: which file an
 * include loads is a static fact, and nothing about it depends on taint.
 *
 * Sites that will not resolve are recorded rather than dropped. An include the
 * engine cannot follow is a hole in the analysis exactly as large as the file
 * behind it, and the count is the only thing that makes it visible.
 */
final class IncludeGraphBuilder
{
    public function __construct(
        private readonly IncludeResolver $resolver,
        private readonly string $projectRoot,
    ) {
    }

    /**
     * @param list<FunctionContext> $contexts
     */
    public function build(array $contexts): IncludeGraph
    {
        $graph = new IncludeGraph();

        foreach ($contexts as $context) {
            $file = $context->file->relativePath;
            $absolute = $this->projectRoot . '/' . $file;
            $offset = 0;

            foreach (BlockOrder::of($context->func->cfg) as $block) {
                foreach ($block->children as $op) {
                    if (! $op instanceof Op\Expr\Include_) {
                        continue;
                    }

                    // Line alone is not unique: `include A; include B;` on one
                    // line is legal, if unpleasant.
                    $site = IncludeGraph::siteKey($file, $op->getLine(), $offset++);
                    $targets = $this->resolver->resolve($op, $absolute);

                    if ($targets === []) {
                        $graph->recordUnresolved(
                            $file,
                            $op->getLine(),
                            'the path could not be resolved to a file in the scan',
                        );

                        continue;
                    }

                    $graph->record($site, $targets);
                }
            }
        }

        return $graph;
    }
}
