<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * The parameters a function uses as an array key, or in the glue it joins
 * an array with.
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
 * or write in the body. It counts too when it is part of the glue of an
 * `implode()`, whose text decides whether the joined elements keep their
 * quotes:
 *
 * ```php
 * protected function get_status_subquery( $query_args, $operator = 'AND' ) {
 *     return implode( " $operator ", $subqueries );
 * }
 * ```
 */
final class KeyParameters
{
    /** How far a key is followed back through copies. */
    private const MAX_HOPS = 16;

    /**
     * The key parameters, and the ones among them that are part of a glue,
     * which a call that leaves one out binds to its default. See
     * {@see FunctionSummary::$glueParameters}. One walk of the body finds
     * both.
     *
     * @param array<string, list<int>> $glues the functions that join with a glue, and its position: see
     *                                  {@see \Enshrined\WpTaint\Registry\Registry::glueArguments()}
     *
     * @return array{list<int>, list<int>} parameter indexes, ascending
     */
    public static function of(Func $func, array $glues = []): array
    {
        [$keys, $inGlues] = self::found($func, $glues);
        $list = array_keys($keys + $inGlues);
        sort($list);
        $glued = array_keys($inGlues);
        sort($glued);

        return [$list, $glued];
    }

    /**
     * Whether every key parameter only picks an element. Each use of it, or
     * of a copy of it, is one of these:
     *
     * - an element key, `$this->data[ $prop ]`, to read or to write
     * - a test for the key, `isset()`, `empty()` or `array_key_exists()`
     * - a comparison
     * - a part of a joined string, `'acme_get_' . $prop`
     *
     * WooCommerce's `WC_Data::get_prop()` and `set_prop()` are two such
     * functions. A variant of one differs from its own run mostly in the
     * element it reads or writes. It hands the key itself to no callee. A
     * joined string can still reach one, `$this->other( 'x_' . $prop )`,
     * and ask for a variant of it, which counts against the callee's own
     * cap. See {@see FunctionSummary::$picksElements}.
     *
     * @param list<int> $keys the key parameters: see {@see of()}
     */
    public static function onlyPick(Func $func, array $keys): bool
    {
        if ($keys === []) {
            return false;
        }

        $copies = [];

        foreach (array_values($func->params) as $index => $param) {
            if (in_array($index, $keys, true)) {
                $copies[spl_object_id($param->result)] = true;
            }
        }

        $ops = [];

        foreach (BlockOrder::of($func->cfg) as $block) {
            array_push($ops, ...$block->phi, ...$block->children);
        }

        $copies = self::copiesOf($ops, $copies);

        foreach ($ops as $op) {
            foreach ($op->getVariableNames() as $name) {
                if (! is_string($name) || $op->isWriteVariable($name)) {
                    continue;
                }

                foreach (self::operandsIn(OperandHelper::readProperty($op, $name)) as $operand) {
                    if (isset($copies[spl_object_id($operand)]) && ! self::picks($op, $name, $operand)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    /**
     * The parameters and every copy of them, through an assignment, a
     * narrowed type or a phi. Grown until a pass adds nothing, so a loop's
     * phi is found however the blocks are ordered.
     *
     * @param list<Op>         $ops
     * @param array<int, true> $copies an operand's object id => true
     *
     * @return array<int, true>
     */
    private static function copiesOf(array $ops, array $copies): array
    {
        do {
            $added = false;

            foreach ($ops as $op) {
                $into = match (true) {
                    $op instanceof Op\Expr\Assign => isset($copies[spl_object_id($op->expr)])
                        ? [$op->var, $op->result]
                        : [],
                    $op instanceof Op\Expr\Assertion => isset($copies[spl_object_id($op->expr)]) ? [$op->result] : [],
                    $op instanceof Op\Phi => self::anyIn($op->vars, $copies) ? [$op->result] : [],
                    default => [],
                };

                foreach ($into as $operand) {
                    if (! isset($copies[spl_object_id($operand)])) {
                        $copies[spl_object_id($operand)] = true;
                        $added = true;
                    }
                }
            }
        } while ($added);

        return $copies;
    }

    /**
     * @param array<array-key, mixed> $operands
     * @param array<int, true>        $copies
     */
    private static function anyIn(array $operands, array $copies): bool
    {
        foreach ($operands as $operand) {
            if ($operand instanceof Operand && isset($copies[spl_object_id($operand)])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<Operand>
     */
    private static function operandsIn(mixed $slot): array
    {
        if ($slot instanceof Operand) {
            return [$slot];
        }

        if (! is_array($slot)) {
            return [];
        }

        return array_values(array_filter($slot, static fn (mixed $o): bool => $o instanceof Operand));
    }

    /**
     * Whether a parameter in this slot of this op only picks an element, or
     * is copied, so the copy's own uses decide.
     */
    private static function picks(Op $op, string $slot, Operand $operand): bool
    {
        return match (true) {
            $op instanceof Op\Expr\ArrayDimFetch => $slot === 'dim',
            $op instanceof Op\Expr\Assign, $op instanceof Op\Expr\Assertion => $slot === 'expr',
            $op instanceof Op\Phi,
            $op instanceof Op\Expr\Isset_,
            $op instanceof Op\Expr\Empty_,
            $op instanceof Op\Expr\BinaryOp\Identical,
            $op instanceof Op\Expr\BinaryOp\NotIdentical,
            $op instanceof Op\Expr\BinaryOp\Equal,
            $op instanceof Op\Expr\BinaryOp\NotEqual,
            $op instanceof Op\Expr\BinaryOp\Concat,
            $op instanceof Op\Expr\ConcatList => true,
            $op instanceof Op\Expr\FuncCall,
            $op instanceof Op\Expr\NsFuncCall => $slot === 'args' && ($op->args[0] ?? null) === $operand
                && self::testsForKey($op),
            default => false,
        };
    }

    /**
     * `array_key_exists( $prop, $this->data )`, which reads no element.
     */
    private static function testsForKey(Op\Expr\FuncCall|Op\Expr\NsFuncCall $call): bool
    {
        $name = OperandHelper::literalString($call->name);

        return $name !== null
            && in_array(strtolower(ltrim($name, '\\')), ['array_key_exists', 'key_exists'], true);
    }

    /**
     * @param array<string, list<int>> $glues
     *
     * @return array{array<int, true>, array<int, true>} the parameters used as a key, and the ones in a glue
     */
    private static function found(Func $func, array $glues): array
    {
        $indexes = [];

        foreach (array_values($func->params) as $index => $param) {
            if (! $param->variadic) {
                $indexes[spl_object_id($param->result)] = $index;
            }
        }

        if ($indexes === []) {
            return [[], []];
        }

        $keys = [];
        $inGlues = [];

        foreach (BlockOrder::of($func->cfg) as $block) {
            foreach ($block->children as $op) {
                foreach (self::glueOf($op, $glues) as $glue) {
                    foreach (self::parametersIn($glue, $indexes, 0) as $index) {
                        $inGlues[$index] = true;
                    }
                }

                if (! $op instanceof Op\Expr\ArrayDimFetch || ! $op->dim instanceof Operand) {
                    continue;
                }

                $index = self::parameterOf($op->dim, $indexes);

                if ($index !== null) {
                    $keys[$index] = true;
                }
            }
        }

        return [$keys, $inGlues];
    }

    /**
     * The glue a call joins with, when it is one of `$glues` and has an array
     * to join. A lone argument is the array itself.
     *
     * @param array<string, list<int>> $glues
     *
     * @return list<Operand>
     */
    private static function glueOf(Op $op, array $glues): array
    {
        if (! $op instanceof Op\Expr\FuncCall && ! $op instanceof Op\Expr\NsFuncCall) {
            return [];
        }

        $name = OperandHelper::literalString($op->name);
        $positions = $name === null ? [] : ($glues[strtolower(ltrim($name, '\\'))] ?? []);

        if (count($op->args) < 2) {
            return [];
        }

        $found = [];

        foreach ($positions as $at) {
            if (($op->args[$at] ?? null) instanceof Operand) {
                $found[] = $op->args[$at];
            }
        }

        return $found;
    }

    /**
     * The parameters a string is built from: the parameter itself, a copy
     * of it, or any part of a concatenation or interpolation of them.
     *
     * @param array<int, int> $indexes a parameter operand's object id => its index
     *
     * @return list<int>
     */
    private static function parametersIn(Operand $operand, array $indexes, int $hops): array
    {
        if ($hops > self::MAX_HOPS) {
            return [];
        }

        if (isset($indexes[spl_object_id($operand)])) {
            return [$indexes[spl_object_id($operand)]];
        }

        $op = OperandHelper::definingOp($operand);
        $parts = match (true) {
            $op instanceof Op\Expr\Assign => [$op->expr],
            $op instanceof Op\Expr\ConcatList => $op->list,
            $op instanceof Op\Expr\BinaryOp\Concat => [$op->left, $op->right],
            default => [],
        };
        $found = [];

        foreach ($parts as $part) {
            if ($part instanceof Operand) {
                array_push($found, ...self::parametersIn($part, $indexes, $hops + 1));
            }
        }

        return $found;
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
