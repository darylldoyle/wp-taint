<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Collects every `define()` call and `const` declaration in the scan.
 *
 * Runs once, before analysis, for the same reason the hook graph does:
 * constants are static facts about the code and nothing about them depends on
 * taint.
 *
 * Two passes over the same contexts, because a constant is routinely defined in
 * terms of another one:
 *
 * ```php
 * define( 'ACME_FILE', __FILE__ );
 * define( 'ACME_DIR', dirname( ACME_FILE ) . '/' );
 * ```
 *
 * The first pass resolves what it can from literals; the second re-runs with
 * those in hand. Two rather than a fixed point because chains longer than that
 * are rare and the cost is a whole extra walk.
 */
final class ConstantTableBuilder
{
    private const PASSES = 2;

    public function __construct(private readonly ValueResolver $values)
    {
    }

    /**
     * @param list<FunctionContext> $contexts
     */
    public function build(array $contexts): ConstantTable
    {
        $table = new ConstantTable();

        for ($pass = 0; $pass < self::PASSES; $pass++) {
            $resolver = $this->values->withConstants($table);

            foreach ($contexts as $context) {
                foreach (BlockOrder::of($context->func->cfg) as $block) {
                    foreach ($block->children as $op) {
                        $this->collect($table, $resolver, $op);
                    }
                }
            }
        }

        return $table;
    }

    private function collect(ConstantTable $table, ValueResolver $resolver, mixed $op): void
    {
        // `const NAME = 'value';` — php-cfg gives it its own terminal, with the
        // name already resolved.
        if ($op instanceof Op\Terminal\Const_) {
            $name = OperandHelper::literalString($op->name);

            if ($name !== null) {
                $table->define($name, self::single($resolver->strings($op->value)));
            }

            return;
        }

        if (! $op instanceof Op\Expr\FuncCall && ! $op instanceof Op\Expr\NsFuncCall) {
            return;
        }

        if (! self::isDefine($op)) {
            return;
        }

        $arguments = [];

        foreach ($op->args as $argument) {
            if ($argument instanceof Operand) {
                $arguments[] = $argument;
            }
        }

        if (count($arguments) < 2) {
            return;
        }

        $name = OperandHelper::literalString($arguments[0]);

        if ($name === null) {
            return;
        }

        $table->define($name, self::single($resolver->strings($arguments[1])));
    }

    /**
     * A constant with several possible values is recorded as unresolvable
     * rather than as any one of them.
     *
     * The value resolver returns sets everywhere else, and a set would be
     * defensible here too — but a constant is a single value at runtime, and
     * carrying an "either" through path resolution would produce includes of
     * files the build never actually loads.
     *
     * @param list<string> $values
     */
    private static function single(array $values): ?string
    {
        return count($values) === 1 ? $values[0] : null;
    }

    private static function isDefine(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): bool
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        foreach ($names as $name) {
            if ($name !== null && strtolower(ltrim($name, '\\')) === 'define') {
                return true;
            }
        }

        return false;
    }
}
