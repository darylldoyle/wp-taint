<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Follows an operand back to the constant values it can hold.
 *
 * WordPress code names things with strings constantly — callbacks, hook names,
 * class names for `new $class` — and a taint analyser that treats every one of
 * those as opaque gives up exactly where the interesting flows are. This walks
 * the SSA graph backwards until it either lands on literals or runs out of
 * things it can follow.
 *
 * A **set**, not a value: a phi node at a branch join genuinely holds one of
 * several strings, and picking one would be a guess. Returning all of them lets
 * the caller union the effects, which is the sound answer.
 *
 * Returning an empty set means "no idea", never "no values". The two have very
 * different consequences downstream and callers have to tell them apart.
 */
final class ValueResolver
{
    /**
     * How far back to walk before giving up.
     *
     * Chains longer than this exist, but they are almost always a sign the
     * value is genuinely computed rather than merely passed around, in which
     * case the answer would be "no idea" anyway.
     */
    private const MAX_DEPTH = 12;

    /**
     * How many distinct values to carry before declaring defeat.
     *
     * A concat of two phis of four values each is sixteen strings, and past
     * that point the "resolved" set is broad enough to be worthless while
     * still costing a call site's worth of analysis each.
     */
    private const MAX_VALUES = 12;

    /**
     * The constant strings this operand can hold.
     *
     * @return list<string> empty when the value cannot be pinned down
     */
    public function strings(Operand $operand, int $depth = 0): array
    {
        if ($depth > self::MAX_DEPTH) {
            return [];
        }

        $literal = OperandHelper::literalString($operand);

        if ($literal !== null) {
            return [$literal];
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            return [];
        }

        return match (true) {
            $definition instanceof Op\Expr\Assign => $this->strings($definition->expr, $depth + 1),
            $definition instanceof Op\Phi => $this->fromPhi($definition, $depth),
            $definition instanceof Op\Expr\ConcatList => $this->fromParts($definition->list, $depth),
            $definition instanceof Op\Expr\BinaryOp\Concat => $this->fromParts(
                [$definition->left, $definition->right],
                $depth,
            ),
            default => [],
        };
    }

    /**
     * The literal pair behind `array( $receiver, 'method' )`.
     *
     * PHP's array callable form. The first element is either an object operand
     * or a class-name string, and the callable resolver needs to tell those
     * apart, so the operand is handed back rather than resolved here.
     *
     * @return array{0: Operand, 1: list<string>}|null
     */
    public function callableArray(Operand $operand, int $depth = 0): ?array
    {
        if ($depth > self::MAX_DEPTH) {
            return null;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->callableArray($definition->expr, $depth + 1);
        }

        if (! $definition instanceof Op\Expr\Array_) {
            return null;
        }

        $values = [];

        foreach ($definition->values as $value) {
            if ($value instanceof Operand) {
                $values[] = $value;
            }
        }

        if (count($values) !== 2) {
            return null;
        }

        $methods = $this->strings($values[1], $depth + 1);

        return $methods === [] ? null : [$values[0], $methods];
    }

    /**
     * Every branch of a join contributes, because at runtime any of them can be
     * the one taken.
     *
     * @return list<string>
     */
    private function fromPhi(Op\Phi $phi, int $depth): array
    {
        $values = [];

        foreach ($phi->vars as $var) {
            if (! $var instanceof Operand) {
                continue;
            }

            foreach ($this->strings($var, $depth + 1) as $value) {
                if (! in_array($value, $values, true)) {
                    $values[] = $value;
                }
            }

            if (count($values) > self::MAX_VALUES) {
                return [];
            }
        }

        return $values;
    }

    /**
     * A concatenation resolves only if every part does.
     *
     * One unresolvable part means the whole string is unknown — `'render_' .
     * $mode` where `$mode` is a parameter could be anything, and treating the
     * prefix as the answer would resolve the call to the wrong function.
     *
     * @param array<array-key, mixed> $parts
     *
     * @return list<string>
     */
    private function fromParts(array $parts, int $depth): array
    {
        $combinations = [''];

        foreach ($parts as $part) {
            if (! $part instanceof Operand) {
                return [];
            }

            $options = $this->strings($part, $depth + 1);

            if ($options === []) {
                return [];
            }

            $next = [];

            foreach ($combinations as $prefix) {
                foreach ($options as $option) {
                    $next[] = $prefix . $option;
                }
            }

            if (count($next) > self::MAX_VALUES) {
                return [];
            }

            $combinations = $next;
        }

        return array_values(array_unique($combinations));
    }
}
