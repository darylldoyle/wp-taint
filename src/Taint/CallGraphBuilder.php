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
 * disagree about what a call site means. A callback registered on a hook the
 * function dispatches is an edge too, marked as one: it gives the callback a
 * caller, but the authorization walk does not credit a check inside it. See
 * {@see CallGraph}.
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
     * @param iterable<FunctionContext> $contexts
     */
    public function build(iterable $contexts): CallGraph
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
                            $graph->addEdge($context->key, $target->userFunctionKey, $target->viaHook);
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
