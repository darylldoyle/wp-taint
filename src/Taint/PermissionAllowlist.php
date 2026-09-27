<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Request parameters a REST permission callback admits only from a fixed list.
 *
 * WordPress runs a route's permission callback before its callback, and a
 * request it refuses never reaches the callback. So when every path that lets
 * a request through first checks a parameter against a list of literals, the
 * callback reads one of those values:
 *
 * ```php
 * $type = $request->get_param( 'objectType' );
 *
 * if ( in_array( $type, array( 'post', 'term', 'user' ), true ) ) {
 *     return current_user_can( 'edit_posts' );
 * }
 *
 * return false;
 * ```
 *
 * Rank Math's schema routes are written this way. Their callback builds a
 * table name from `objectType`, which read as SQL injection until the check in
 * the permission callback was seen.
 *
 * The check is {@see GuardAnalyzer}'s, asked of the block each permitting
 * return sits in, so it recognises what that recognises: a strict `in_array()`
 * against literals, `array_key_exists()` against a literal array, an anchored
 * `preg_match()`, and the character-class predicates. WordPress refuses a
 * request only for `false`, `null` or a `WP_Error`, so those returns constrain
 * nothing and every other return has to be justified. A return that hands back
 * a helper's answer, given the same request, takes the helper's list, to a
 * small depth. A parameter counts only when every permitting return admits it
 * from a list. A callback that never permits, or whose request this cannot
 * follow, admits nothing.
 *
 * Only a value read into a variable is followed: the guard is tied to its
 * name. `in_array( $request->get_param( 'x' ), … )` admits nothing here, which
 * is the direction that cannot hide a finding.
 */
final class PermissionAllowlist
{
    private const MAX_DEPTH = 3;

    /** @var array<string, array<string, true>> function key and request parameter index => admitted names */
    private array $memo = [];

    public function __construct(
        private readonly UserFunctionTable $functions,
        private readonly FunctionBodies $bodies,
    ) {
    }

    /**
     * The request parameters this callback admits only from a fixed list.
     *
     * @param int $requestIndex which of the function's parameters is the request
     *
     * @return array<string, true>
     */
    public function parametersOf(FunctionContext $context, int $requestIndex = 0, int $depth = 0): array
    {
        $memo = $context->key . '#' . $requestIndex;

        if (isset($this->memo[$memo])) {
            return $this->memo[$memo];
        }

        // Settled as nothing while it is worked out, so a helper that calls
        // back into this one ends there.
        $this->memo[$memo] = [];

        return $this->memo[$memo] = $this->compute($context, $requestIndex, $depth);
    }

    /**
     * @return array<string, true>
     */
    private function compute(FunctionContext $context, int $requestIndex, int $depth): array
    {
        $request = $context->func->params[$requestIndex] ?? null;
        $requestName = $request instanceof Op\Expr\Param ? OperandHelper::literalString($request->name) : null;
        $blocks = BlockOrder::of($context->func->cfg);

        if ($requestName === null || $blocks === []) {
            return [];
        }

        $guards = new GuardAnalyzer();
        $guards->forFunction($blocks);
        $reads = self::parameterReads($blocks, $requestName);

        /** @var array<string, true>|null $admitted */
        $admitted = null;

        foreach ($blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Terminal\Return_ || self::refuses($op->expr)) {
                    continue;
                }

                $here = [];

                foreach ($reads as [$parameter, $variable]) {
                    if (
                        $guards->isGuarded($variable, $block)
                        || ($op->expr !== null && $guards->provesWhenTrue($op->expr, $variable))
                    ) {
                        $here[$parameter] = true;
                    }
                }

                if ($op->expr !== null && $depth < self::MAX_DEPTH) {
                    $here += $this->fromHelper($op->expr, $context, $requestName, $depth);
                }

                $admitted = $admitted === null ? $here : array_intersect_key($admitted, $here);

                if ($admitted === []) {
                    return [];
                }
            }
        }

        return $admitted ?? [];
    }

    /**
     * Every `$x = $request->get_param( 'name' )` and `$x = $request['name']`.
     *
     * @param list<\PHPCfg\Block> $blocks
     *
     * @return list<array{0: string, 1: Operand}> parameter name, the variable it was read into
     */
    private static function parameterReads(array $blocks, string $requestName): array
    {
        $reads = [];

        foreach ($blocks as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Expr\Assign) {
                    continue;
                }

                $parameter = self::parameterRead(OperandHelper::definingOp($op->expr), $requestName);

                if ($parameter !== null) {
                    $reads[] = [$parameter, $op->var];
                }
            }
        }

        return $reads;
    }

    private static function parameterRead(?Op $read, string $requestName): ?string
    {
        if ($read instanceof Op\Expr\MethodCall) {
            $method = OperandHelper::literalString($read->name);
            $argument = $read->args[0] ?? null;

            return $method !== null && strtolower($method) === 'get_param'
                && self::names($read->var, $requestName)
                && $argument instanceof Operand
                ? OperandHelper::literalString($argument)
                : null;
        }

        if ($read instanceof Op\Expr\ArrayDimFetch && $read->dim instanceof Operand) {
            return self::names($read->var, $requestName) ? OperandHelper::literalString($read->dim) : null;
        }

        return null;
    }

    /**
     * Whether returning this refuses the request: `false`, `null`, a
     * `WP_Error`, or nothing at all.
     */
    private static function refuses(?Operand $value, int $depth = 0): bool
    {
        if ($value === null) {
            return true;
        }

        if ($value instanceof Operand\Literal) {
            return $value->value === false || $value->value === null;
        }

        if ($depth > self::MAX_DEPTH) {
            return false;
        }

        $definition = OperandHelper::definingOp($value);

        return match (true) {
            $definition instanceof Op\Expr\Assign => self::refuses($definition->expr, $depth + 1),
            $definition instanceof Op\Expr\ConstFetch => in_array(
                strtolower(ltrim(OperandHelper::literalString($definition->name) ?? '', '\\')),
                ['false', 'null'],
                true,
            ),
            $definition instanceof Op\Expr\New_ => strtolower(
                ltrim(OperandHelper::literalString($definition->class) ?? '', '\\'),
            ) === 'wp_error',
            default => false,
        };
    }

    /**
     * What a helper admits, when this return hands back its answer and it was
     * given the same request.
     *
     * @return array<string, true>
     */
    private function fromHelper(Operand $value, FunctionContext $context, string $requestName, int $depth): array
    {
        $call = OperandHelper::definingOp($value);

        while ($call instanceof Op\Expr\Assign) {
            $call = OperandHelper::definingOp($call->expr);
        }

        if (
            ! $call instanceof Op\Expr\FuncCall
            && ! $call instanceof Op\Expr\StaticCall
            && ! $call instanceof Op\Expr\MethodCall
        ) {
            return [];
        }

        $key = match (true) {
            $call instanceof Op\Expr\FuncCall => self::functionKey($call->name),
            $call instanceof Op\Expr\StaticCall => $this->staticMethodKey($call, $context),
            default => $this->ownMethodKey($call, $context),
        };

        $meta = $key === null ? null : $this->functions->get($key);

        if ($meta === null) {
            return [];
        }

        foreach (array_values($call->args) as $index => $argument) {
            if ($argument instanceof Operand && self::names($argument, $requestName)) {
                return $this->parametersOf($this->bodies->context($meta), $index, $depth + 1);
            }
        }

        return [];
    }

    private static function functionKey(Operand $name): ?string
    {
        $literal = OperandHelper::literalString($name);

        return $literal === null ? null : strtolower(ltrim($literal, '\\'));
    }

    private function staticMethodKey(Op\Expr\StaticCall $call, FunctionContext $context): ?string
    {
        $class = OperandHelper::literalString($call->class);
        $method = OperandHelper::literalString($call->name);

        if ($class === null || $method === null) {
            return null;
        }

        if (in_array(strtolower($class), ['self', 'static'], true)) {
            $class = $context->className;
        }

        return $class === null || strtolower($class) === 'parent'
            ? null
            : $this->functions->resolveMethodKey($class, $method);
    }

    private function ownMethodKey(Op\Expr\MethodCall $call, FunctionContext $context): ?string
    {
        $method = OperandHelper::literalString($call->name);

        return $method === null || $context->className === null || ! self::names($call->var, 'this')
            ? null
            : $this->functions->resolveMethodKey($context->className, $method);
    }

    /**
     * Whether an operand is the named variable, however SSA renamed it.
     */
    private static function names(Operand $operand, string $name): bool
    {
        foreach ([$operand, $operand instanceof Operand\Temporary ? $operand->original : null] as $candidate) {
            if (
                $candidate instanceof Operand\Variable
                && $candidate->name instanceof Operand\Literal
                && $candidate->name->value === $name
            ) {
                return true;
            }
        }

        return false;
    }
}
