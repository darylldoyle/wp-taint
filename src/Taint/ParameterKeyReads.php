<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * The keys a function reads each parameter through, for a parameter it reads
 * only through literal keys.
 *
 * ```php
 * function describe( $field ) {
 *     return array( 'tip' => $field['desc'] );
 * }
 *
 * $field['value'] = get_option( 'x' );
 * $parts          = describe( $field );   // $field['value'] does not get in
 * ```
 *
 * A caller hands its callee the whole argument. Without this, the callee got
 * every element's taint, and the stored option above came back out of
 * `describe()` under `tip`. The callee can see only the keys it reads, so the
 * caller hands it those elements, and whatever the array carries as a whole
 * or under a computed key.
 *
 * Any other use of the parameter reads it whole: passing it on, copying it,
 * returning it, iterating it, reading it with a computed key, or a closure
 * that captures it. So does anything that reads the function's variables
 * without naming them: `func_get_args()`, `compact()`, `get_defined_vars()`,
 * `debug_backtrace()`, a variable variable, `include`, `eval`, and an arrow
 * function, which captures what it uses without saying so.
 *
 * Some uses read nothing of the value. A type check, `count()`, `isset()`,
 * `empty()`, a comparison, or a condition learns one fact about the value,
 * and none of its content can come out of it.
 *
 * The parameter is followed by name. A read of `$field['x']` after `$field`
 * was reassigned still counts as a read of the parameter. That can only add
 * keys, which is the direction that cannot hide a finding. A variadic
 * parameter is a list of arguments, so its keys are not an argument's.
 */
final class ParameterKeyReads
{
    /**
     * Functions that read the calling function's variables, or its arguments,
     * without naming them. PHP refuses to call any of the first four
     * dynamically, so a call by name is the only way to reach them.
     */
    private const SCOPE_READERS = [
        'func_get_args' => true,
        'func_get_arg' => true,
        'get_defined_vars' => true,
        'compact' => true,
        'debug_backtrace' => true,
        'debug_print_backtrace' => true,
    ];

    /**
     * PHP's functions whose answer about a value carries none of its content.
     */
    private const CONTENT_FREE = [
        'is_array' => true,
        'is_string' => true,
        'is_numeric' => true,
        'is_int' => true,
        'is_integer' => true,
        'is_long' => true,
        'is_float' => true,
        'is_double' => true,
        'is_bool' => true,
        'is_null' => true,
        'is_object' => true,
        'is_scalar' => true,
        'is_iterable' => true,
        'is_countable' => true,
        'is_resource' => true,
        'array_is_list' => true,
        'count' => true,
        'sizeof' => true,
        'gettype' => true,
        'get_debug_type' => true,
        'array_key_exists' => true,
        'key_exists' => true,
        'in_array' => true,
    ];

    public function __construct(private readonly UserFunctionTable $functions)
    {
    }

    /**
     * @return array<int, list<array-key>> parameter index => the keys it is read through, sorted
     */
    public function of(Func $func): array
    {
        /** @var array<string, int> $indexes */
        $indexes = [];

        foreach (array_values($func->params) as $index => $param) {
            $name = OperandHelper::literalString($param->name);

            if ($name !== null && ! $param->variadic) {
                $indexes[$name] = $index;
            }
        }

        if ($indexes === []) {
            return [];
        }

        /** @var array<string, array<array-key, true>> $keys */
        $keys = [];

        foreach (array_keys($indexes) as $name) {
            $keys[$name] = [];
        }

        foreach (BlockOrder::of($func->cfg) as $block) {
            foreach ($block->children as $op) {
                if ($this->readsScope($op)) {
                    return [];
                }

                foreach ($this->reads($op) as [$name, $key]) {
                    if (! isset($keys[$name])) {
                        continue;
                    }

                    if ($key === null) {
                        unset($keys[$name]);

                        continue;
                    }

                    $keys[$name][$key] = true;
                }
            }
        }

        $byIndex = [];

        foreach ($indexes as $name => $index) {
            if (! isset($keys[$name])) {
                continue;
            }

            $list = array_keys($keys[$name]);
            sort($list);
            $byIndex[$index] = $list;
        }

        return $byIndex;
    }

    private function readsScope(Op $op): bool
    {
        if (
            $op instanceof Op\Expr\ArrowFunction
            || $op instanceof Op\Expr\Include_
            || $op instanceof Op\Expr\Eval_
            || $op instanceof Op\Expr\VarVar
        ) {
            return true;
        }

        if ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall) {
            $name = OperandHelper::literalString($op->name);

            if ($name !== null && isset(self::SCOPE_READERS[strtolower(ltrim($name, '\\'))])) {
                return true;
            }
        }

        foreach (OperandHelper::operandsOf($op) as $operand) {
            if ($operand instanceof Operand\Variable && ! $operand->name instanceof Operand\Literal) {
                return true;
            }
        }

        return false;
    }

    /**
     * The parameters this op reads, each with the literal key it reads it
     * through, or null for a read of the whole value.
     *
     * @return list<array{0: string, 1: array-key|null}>
     */
    private function reads(Op $op): array
    {
        if ($op instanceof Op\Expr\Param || $op instanceof Op\Expr\Assertion) {
            // Declares the parameter, or narrows its type under a new name.
            return [];
        }

        if ($op instanceof Op\Expr\ArrayDimFetch) {
            $reads = [];
            $name = self::nameOf($op->var);
            $appends = $op->dim === null || $op->dim instanceof Operand\NullOperand;

            // `$field[] = $x` appends. PHP cannot read with an empty key.
            if ($name !== null && ! $appends) {
                $reads[] = [$name, OperandHelper::literalKey($op->dim)];
            }

            $key = $appends ? null : self::nameOf($op->dim);

            if ($key !== null) {
                $reads[] = [$key, null];
            }

            return $reads;
        }

        if ($this->contentFree($op)) {
            return [];
        }

        $reads = [];

        foreach ($op->getVariableNames() as $property) {
            if (! is_string($property) || $op->isWriteVariable($property)) {
                continue;
            }

            foreach (self::operandsIn($op, $property) as $operand) {
                $name = self::nameOf($operand);

                if ($name !== null) {
                    $reads[] = [$name, null];
                }
            }
        }

        return $reads;
    }

    private function contentFree(Op $op): bool
    {
        if (
            $op instanceof Op\Expr\Isset_
            || $op instanceof Op\Expr\Empty_
            || $op instanceof Op\Expr\BooleanNot
            || $op instanceof Op\Expr\InstanceOf_
            || $op instanceof Op\Expr\Cast\Bool_
            || $op instanceof Op\Expr\Cast\Int_
            || $op instanceof Op\Expr\Cast\Double
            || $op instanceof Op\Expr\BinaryOp\Equal
            || $op instanceof Op\Expr\BinaryOp\NotEqual
            || $op instanceof Op\Expr\BinaryOp\Identical
            || $op instanceof Op\Expr\BinaryOp\NotIdentical
            || $op instanceof Op\Expr\BinaryOp\Smaller
            || $op instanceof Op\Expr\BinaryOp\SmallerOrEqual
            || $op instanceof Op\Expr\BinaryOp\Greater
            || $op instanceof Op\Expr\BinaryOp\GreaterOrEqual
            || $op instanceof Op\Expr\BinaryOp\Spaceship
            || $op instanceof Op\Stmt\JumpIf
            || $op instanceof Op\Stmt\Switch_
        ) {
            return true;
        }

        if ($op instanceof Op\Expr\FuncCall) {
            $name = OperandHelper::literalString($op->name);

            return $name !== null && isset(self::CONTENT_FREE[strtolower(ltrim($name, '\\'))]);
        }

        if ($op instanceof Op\Expr\NsFuncCall) {
            // `is_array()` inside a namespace is the namespace's own function
            // when the scan declares one, and PHP's otherwise.
            $local = OperandHelper::literalString($op->nsName);
            $name = OperandHelper::literalString($op->name);

            return $local !== null
                && $name !== null
                && $this->functions->get(strtolower(ltrim($local, '\\'))) === null
                && isset(self::CONTENT_FREE[strtolower(ltrim($name, '\\'))]);
        }

        return false;
    }

    /**
     * @return list<Operand>
     */
    private static function operandsIn(Op $op, string $property): array
    {
        /** @var array<string, mixed> $vars */
        $vars = get_object_vars($op);
        $value = $vars[$property] ?? null;

        if ($value instanceof Operand) {
            return [$value];
        }

        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $item): bool => $item instanceof Operand));
    }

    /**
     * The variable an operand is, however SSA renamed it.
     */
    private static function nameOf(Operand $operand): ?string
    {
        $variable = $operand instanceof Operand\Temporary ? $operand->original : $operand;

        if (! $variable instanceof Operand\Variable || ! $variable->name instanceof Operand\Literal) {
            return null;
        }

        $name = $variable->name->value;

        return is_string($name) && $name !== 'this' ? $name : null;
    }
}
