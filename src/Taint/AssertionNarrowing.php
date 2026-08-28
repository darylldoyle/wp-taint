<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Assertion;
use PHPCfg\Assertion\NegatedAssertion;
use PHPCfg\Assertion\TypeAssertion;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * What a branch condition proves about a value on the branch it guards.
 *
 * ```php
 * $id = $_GET['id'];
 * if ( ! is_int( $id ) ) {
 *     return;
 * }
 * echo $id;            // an int by now, and an int carries no payload
 * ```
 *
 * The engine keeps one taint state per function rather than one per block,
 * which is what makes its fixed point cheap and what appeared to put this out
 * of reach. It is not: php-cfg already writes the answer into SSA.
 *
 * ```
 * Block#2 (guard taken)              Block#3 (fall-through)
 *   Expr_Assertion<not(type(int))>     Expr_Assertion<not(not(type(int))>
 *     expr:   Var#3<$id>                 expr:   Var#3<$id>
 *     result: Var#7<$id>                 result: Var#8<$id>
 * ```
 *
 * Each branch gets its *own operand* for the same variable, so the two paths
 * are already distinguishable without per-block state. All that was missing was
 * reading the assertion instead of passing taint straight through it.
 *
 * ## What narrows, and what does not
 *
 * Only a positive assertion to a numeric or boolean type. An `int` cannot carry
 * a quote, an angle bracket or a semicolon, so it is safe in every context this
 * engine models. `is_string()` proves nothing — the dangerous values are
 * strings. A *negated* numeric assertion proves nothing either: "not an int"
 * says the value could be anything.
 *
 * Nested negations are unwrapped by parity, because the fall-through branch of
 * `if ( ! is_int( $x ) )` carries `not(not(type(int)))`, which is positive.
 *
 * ## Why the operands must differ
 *
 * `isset($x)` and `!empty($x)` produce an assertion whose result is an operand
 * *already written by the op that produced the value*. Narrowing there gives
 * one operand two writers with different answers, which is this project's
 * recurring cause of a fixed point that never settles — five separate
 * non-convergences have come from exactly that. When the operands are the same
 * the assertion is passed through, as it always was.
 */
final class AssertionNarrowing
{
    /**
     * Types whose values cannot carry a payload in any modelled context.
     *
     * `numeric` is php-cfg's assertion for `is_numeric()`, which admits
     * numeric *strings* — `"1e3"`, `" 12"`. None of those carry a quote or a
     * bracket either, so the conclusion holds.
     */
    private const HARMLESS = ['int', 'float', 'bool', 'numeric'];

    /**
     * Does this assertion prove the value can no longer carry a payload?
     */
    public static function narrows(Op\Expr\Assertion $op): bool
    {
        // Same operand in and out: one operand, two writers, and a fixed point
        // that oscillates. See the class docblock.
        if ($op->result === $op->expr) {
            return false;
        }

        return self::provesHarmless($op->assertion, true);
    }

    /**
     * @param bool $positive whether an even number of negations has been seen
     */
    private static function provesHarmless(Assertion $assertion, bool $positive): bool
    {
        if ($assertion instanceof NegatedAssertion) {
            $inner = $assertion->value;

            // A negation wraps exactly one assertion in the shapes php-cfg
            // emits; anything else is a union or intersection this does not
            // reason about.
            if (! is_array($inner)) {
                return false;
            }

            $values = array_values($inner);

            if (count($values) !== 1) {
                return false;
            }

            return self::provesHarmless($values[0], ! $positive);
        }

        if (! $positive || ! $assertion instanceof TypeAssertion) {
            return false;
        }

        $value = $assertion->value;

        return $value instanceof Operand\Literal
            && is_string($value->value)
            && in_array(strtolower($value->value), self::HARMLESS, true);
    }
}
