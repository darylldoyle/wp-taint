<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\ClassTypeMap;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ReceiverResolver;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Finds every `add_action()` and `add_filter()` in the scanned code.
 *
 * Works over the CFG rather than the AST, for two reasons. The value resolver
 * lives there, and hook names are routinely built rather than written —
 * `"wp_ajax_{$action}"` is the idiom the AST-based resolver could never follow.
 * And callbacks resolve through the same {@see CallableResolver} the rest of
 * the analysis uses, so a hook edge and a `call_user_func()` edge cannot
 * disagree about what `array( $this, 'render' )` means.
 *
 * Runs once, before the taint pass. Registrations are static facts about the
 * code; nothing about them depends on taint.
 */
final class HookGraphBuilder
{
    /**
     * The two registration functions, and the argument layout they share.
     *
     * `add_action()` is `add_filter()` under the hood in WordPress, and the
     * signatures are identical.
     */
    private const REGISTRARS = ['add_action', 'add_filter'];

    public function __construct(
        private readonly CallableResolver $callables,
        private readonly ValueResolver $values,
        private readonly ReceiverResolver $receivers,
    ) {
    }

    /**
     * @param list<FunctionContext> $contexts
     */
    public function build(array $contexts): HookGraph
    {
        $graph = new HookGraph();

        foreach ($contexts as $context) {
            $this->collect($graph, $context);
        }

        return $graph;
    }

    private function collect(HookGraph $graph, FunctionContext $context): void
    {
        $types = new ClassTypeMap();

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\FuncCall) {
                    continue;
                }

                $name = OperandHelper::literalString($op->name);

                if ($name === null || ! in_array(strtolower($name), self::REGISTRARS, true)) {
                    continue;
                }

                $this->record($graph, $op, $context, $types);
            }
        }
    }

    private function record(
        HookGraph $graph,
        Op\Expr\FuncCall $op,
        FunctionContext $context,
        ClassTypeMap $types,
    ): void {
        $arguments = [];

        foreach ($op->args as $argument) {
            if ($argument instanceof Operand) {
                $arguments[] = $argument;
            }
        }

        if (count($arguments) < 2) {
            return;
        }

        // A hook name that resolves to several strings registers the callback
        // on all of them. `add_action( $is_admin ? 'admin_init' : 'init', $cb )`
        // genuinely does run in both places.
        $names = $this->values->strings($arguments[0]);
        $priority = $this->intArgument($arguments[2] ?? null, 10);
        $accepted = $this->intArgument($arguments[3] ?? null, 1);

        $callbacks = $this->callables->resolve(
            $arguments[1],
            [],
            $context,
            $types,
            $this->receivers,
        );

        if ($callbacks === []) {
            return;
        }

        // An empty name is the wildcard: the registration exists but we cannot
        // say which hook it is on, so every dispatch has to consider it.
        foreach ($names === [] ? [''] : $names as $hook) {
            foreach ($callbacks as $callback) {
                $graph->add(new HookRegistration(
                    $hook,
                    $callback,
                    $context->file->relativePath,
                    $op->getLine(),
                    $priority,
                    $accepted,
                ));
            }
        }
    }

    private function intArgument(?Operand $operand, int $default): int
    {
        if ($operand === null) {
            return $default;
        }

        $literal = $operand instanceof Operand\Literal ? $operand->value : null;

        return is_int($literal) || is_numeric($literal) ? (int) $literal : $default;
    }
}
