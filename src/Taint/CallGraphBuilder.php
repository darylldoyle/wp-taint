<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Hooks\HookGraph;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;

/**
 * Walks every function body once and records what it calls.
 *
 * Uses the same {@see CallResolver} the taint pass uses, so the two cannot
 * disagree about what a call site means. A callback registered on a hook is an
 * edge like any other: an AJAX handler that does its capability check inside
 * something it hooks is doing a real check, and the walk should find it.
 */
final class CallGraphBuilder
{
    private readonly CallResolver $resolver;

    public function __construct(
        Registry $registry,
        UserFunctionTable $functions,
        ValueResolver $values,
        ReceiverResolver $receivers,
        CallableResolver $callables,
        ?HookGraph $hooks = null,
    ) {
        $this->resolver = new CallResolver($registry, $functions, $callables, $values, $receivers, $hooks);
    }

    /**
     * @param list<FunctionContext> $contexts
     */
    public function build(array $contexts): CallGraph
    {
        $graph = new CallGraph();
        $types = new ClassTypeMap();

        foreach ($contexts as $context) {
            $graph->addFunction($context->key);

            foreach (BlockOrder::of($context->func->cfg) as $block) {
                foreach ($block->children as $op) {
                    if (! $op instanceof Op\Expr) {
                        continue;
                    }

                    foreach ($this->resolver->resolveAll($op, $context, $types) as $target) {
                        if ($target->dynamic) {
                            $graph->markImprecise($context->key);

                            continue;
                        }

                        if ($target->userFunctionKey !== null) {
                            $graph->addEdge($context->key, $target->userFunctionKey);
                        }

                        if ($target->matcher !== null) {
                            $graph->addExternal($context->key, $target->matcher->identity());
                        }
                    }
                }
            }
        }

        return $graph;
    }
}
