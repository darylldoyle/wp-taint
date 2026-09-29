<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * The parameters a function uses as an array key.
 *
 * ```php
 * public function add_sql_clause( $type, $clause ) {
 *     $this->sql_clauses[ $type ][] = $clause;
 * }
 * ```
 *
 * uses `$type` as a key. Summarised once, the write lands under any key,
 * so every clause type reads every other's. A call that names the key,
 * `add_sql_clause( 'where', $x )`, can use a summary of the function with
 * `$type` bound to `'where'`: see {@see FunctionSummary::variantKey()}.
 *
 * A parameter counts when it, or a copy of it, is the key of an element read
 * or write in the body.
 */
final class KeyParameters
{
    /** How far a key is followed back through copies. */
    private const MAX_HOPS = 16;

    /**
     * @return list<int> parameter indexes, ascending
     */
    public static function of(Func $func): array
    {
        $indexes = [];

        foreach (array_values($func->params) as $index => $param) {
            if (! $param->variadic) {
                $indexes[spl_object_id($param->result)] = $index;
            }
        }

        if ($indexes === []) {
            return [];
        }

        $found = [];

        foreach (BlockOrder::of($func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\ArrayDimFetch || ! $op->dim instanceof Operand) {
                    continue;
                }

                $index = self::parameterOf($op->dim, $indexes);

                if ($index !== null) {
                    $found[$index] = true;
                }
            }
        }

        $list = array_keys($found);
        sort($list);

        return $list;
    }

    /**
     * The parameter `$operand` is, or a copy of it is.
     *
     * @param array<int, int> $indexes a parameter operand's object id => its index
     */
    private static function parameterOf(Operand $operand, array $indexes): ?int
    {
        for ($hops = 0; $hops < self::MAX_HOPS; $hops++) {
            $id = spl_object_id($operand);

            if (isset($indexes[$id])) {
                return $indexes[$id];
            }

            $op = OperandHelper::definingOp($operand);

            if (! $op instanceof Op\Expr\Assign) {
                return null;
            }

            $operand = $op->expr;
        }

        return null;
    }
}
