<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Whether a call or a write is on the object `$this` is.
 *
 * A method's own run can hold back its writes to `$this`: see
 * {@see IntraproceduralAnalyzer::holdsBackReceiverWrites()}. The writes it
 * holds back and the calls that run a method on the caller's object are
 * the same ones. A copy of `$this`, `$self = $this`, is `$this` for both.
 */
final class ThisReceiver
{
    /** How many copies deep `$self = $this` is followed. */
    private const MAX_COPIES = 16;

    /**
     * Whether a call runs on `$this`: `$this->m()` or a method call on a copy
     * of `$this`, or `self::m()`, `static::m()` and `parent::m()` in an
     * instance method.
     */
    public static function isCalledOn(Op $op, FunctionContext $context): bool
    {
        return match (true) {
            $op instanceof Op\Expr\MethodCall => self::holds($op->var),
            $op instanceof Op\Expr\StaticCall => self::inInstanceMethod($context) && self::namesOwnClass($op->class),
            default => false,
        };
    }

    /**
     * Whether an operand is `$this`, or a copy of it made by assignment.
     */
    public static function holds(?Operand $operand): bool
    {
        for ($copies = 0; $copies <= self::MAX_COPIES; $copies++) {
            if (OperandHelper::variableName($operand) === 'this') {
                return true;
            }

            $op = OperandHelper::definingOp($operand);

            if (! $op instanceof Op\Expr\Assign) {
                return false;
            }

            $operand = $op->expr;
        }

        return false;
    }

    /**
     * Whether an operand is `$this`, a copy of it, or an object read from a
     * property of `$this`. Which object that property holds depends on the
     * object the run is on, as `$this` does.
     */
    public static function reachedThrough(?Operand $operand): bool
    {
        for ($copies = 0; $copies <= self::MAX_COPIES; $copies++) {
            if (OperandHelper::variableName($operand) === 'this') {
                return true;
            }

            $op = OperandHelper::definingOp($operand);

            if ($op instanceof Op\Expr\PropertyFetch) {
                return self::holds($op->var);
            }

            if (! $op instanceof Op\Expr\Assign) {
                return false;
            }

            $operand = $op->expr;
        }

        return false;
    }

    /**
     * Whether an operand is a copy of `$this` rather than `$this` itself.
     */
    public static function isCopy(?Operand $operand): bool
    {
        return OperandHelper::variableName($operand) !== 'this' && self::holds($operand);
    }

    public static function inInstanceMethod(FunctionContext $context): bool
    {
        return $context->className !== null && ($context->func->flags & Func::FLAG_STATIC) === 0;
    }

    /**
     * Whether a static call's class is `self`, `static` or `parent`, which
     * call on `$this` from an instance method.
     */
    private static function namesOwnClass(Operand $class): bool
    {
        $name = OperandHelper::literalString($class);

        return $name !== null && in_array(strtolower($name), ['self', 'static', 'parent'], true);
    }
}
