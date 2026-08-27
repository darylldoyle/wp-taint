<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

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
        private readonly Registry $registry,
        private readonly ValueResolver $values,
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
            $templateOffset = 0;

            foreach (BlockOrder::of($context->func->cfg) as $block) {
                foreach ($block->children as $op) {
                    if ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall) {
                        $this->recordTemplate($graph, $op, $file, $absolute, $templateOffset);

                        continue;
                    }

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

    /**
     * `get_template_part()` and friends.
     *
     * Recorded in their own key space, because a template call is not an
     * include: the template sees `$args` and the globals, never the caller's
     * locals.
     */
    private function recordTemplate(
        IncludeGraph $graph,
        Op\Expr\FuncCall|Op\Expr\NsFuncCall $op,
        string $file,
        string $absolute,
        int &$offset,
    ): void {
        $loader = null;

        foreach ($this->callNames($op) as $name) {
            $loader = $this->registry->templateLoader(Matcher::function($name));

            if ($loader !== null) {
                break;
            }
        }

        if ($loader === null) {
            return;
        }

        $arguments = [];

        foreach ($op->args as $argument) {
            if ($argument instanceof Operand) {
                $arguments[] = $argument;
            }
        }

        $site = IncludeGraph::templateSiteKey($file, $op->getLine(), $offset++);

        // `load_template()` is handed a path rather than a slug.
        if ($loader->pathArgument !== null) {
            $path = $arguments[$loader->pathArgument] ?? null;
            $targets = $path === null ? [] : $this->resolver->resolvePath($path, $absolute);

            $this->record($graph, $site, $targets, $file, $op->getLine(), 'the template path');

            return;
        }

        $slugs = $loader->slug !== null
            ? [$loader->slug]
            : $this->stringsOf($arguments[$loader->slugArgument ?? 0] ?? null);

        $names = $loader->nameArgument === null
            ? []
            : $this->stringsOf($arguments[$loader->nameArgument] ?? null);

        $this->record(
            $graph,
            $site,
            $this->resolver->resolveTemplate($slugs, $names, $absolute),
            $file,
            $op->getLine(),
            'the template slug',
        );
    }

    /**
     * @param list<string> $targets
     */
    private function record(
        IncludeGraph $graph,
        string $site,
        array $targets,
        string $file,
        int $line,
        string $what,
    ): void {
        if ($targets === []) {
            $graph->recordUnresolved(
                $file,
                $line,
                sprintf('%s could not be resolved to a file in the scan', $what),
            );

            return;
        }

        $graph->record($site, $targets);
    }

    /**
     * @return list<string>
     */
    private function stringsOf(?Operand $operand): array
    {
        return $operand === null ? [] : $this->values->strings($operand);
    }

    /**
     * @return list<string>
     */
    private function callNames(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): array
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        $resolved = [];

        foreach ($names as $name) {
            if ($name !== null) {
                $resolved[] = ltrim($name, '\\');
            }
        }

        return $resolved;
    }
}
