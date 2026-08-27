<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\SourceMap;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * The small, fiddly reads of the php-cfg operand model, in one place.
 *
 * Every one of these is documented in docs/php-cfg-api-notes.md. They are
 * gathered here so that a change to the upstream shape is a change to one file.
 */
final class OperandHelper
{
    /**
     * The source-level variable name behind an SSA operand, without the `$`.
     *
     * After parsing, almost every operand is a `Temporary` whose `original` is
     * the `Variable` it was renamed from, whose `name` is a `Literal`.
     */
    public static function variableName(?Operand $operand): ?string
    {
        if ($operand instanceof Operand\Temporary) {
            $operand = $operand->original;
        }

        if (! $operand instanceof Operand\Variable) {
            return null;
        }

        if (! $operand->name instanceof Operand\Literal) {
            return null;
        }

        $name = $operand->name->value;

        return is_string($name) ? $name : null;
    }

    /**
     * The literal value of an operand, or null when it is not a literal.
     */
    public static function literalValue(?Operand $operand): int|float|string|bool|null
    {
        if (! $operand instanceof Operand\Literal) {
            return null;
        }

        $value = $operand->value;

        return is_scalar($value) ? $value : null;
    }

    public static function literalString(?Operand $operand): ?string
    {
        $value = self::literalValue($operand);

        return is_string($value) ? $value : null;
    }

    /**
     * The op that produced this operand's value.
     *
     * Not simply "the only writer". An operand can legitimately have two:
     * `$arr['k'] = $v` lowers to an `ArrayDimFetch` whose `result` is the
     * temporary, followed by an `Assign` whose `var` is that same temporary.
     * Both call `addWriteRef`, so `$operand->ops` has two entries. The
     * expression that *computed* the value is the fetch, and that is what
     * callers want.
     */
    public static function definingOp(?Operand $operand): ?Op
    {
        if ($operand === null) {
            return null;
        }

        foreach ($operand->ops as $op) {
            if ($op instanceof Op\Expr && $op->result === $operand) {
                return $op;
            }
        }

        foreach ($operand->ops as $op) {
            if (($op instanceof Op\Expr\Assign || $op instanceof Op\Expr\AssignRef) && $op->var === $operand) {
                return $op;
            }
        }

        $only = count($operand->ops) === 1 ? reset($operand->ops) : false;

        return $only instanceof Op ? $only : null;
    }

    /**
     * @return array{line: int, column: int, endColumn: int|null}
     */
    public static function position(?Op $op, SourceMap $sourceMap): array
    {
        if ($op === null) {
            return ['line' => 0, 'column' => 0, 'endColumn' => null];
        }

        // Synthetic ops — the implicit return closing every function — carry no
        // attributes at all. Guess nothing: the reporters omit the caret line
        // when the span is missing.
        if (! $op->hasAttribute('startFilePos')) {
            $line = $op->getLine();

            return ['line' => $line > 0 ? $line : 0, 'column' => 0, 'endColumn' => null];
        }

        $startAttribute = $op->getAttribute('startFilePos');
        $start = is_int($startAttribute) ? $startAttribute : 0;
        $position = $sourceMap->positionAt($start);

        $endColumn = null;

        if ($op->hasAttribute('endFilePos')) {
            $endAttribute = $op->getAttribute('endFilePos');

            if (is_int($endAttribute) && $endAttribute >= $start) {
                $end = $sourceMap->positionAt($endAttribute + 1);

                // Only meaningful when the span stays on one line.
                if ($end['line'] === $position['line']) {
                    $endColumn = $end['column'];
                }
            }
        }

        return [
            'line' => $position['line'],
            'column' => $position['column'],
            'endColumn' => $endColumn,
        ];
    }

    /**
     * Render an operand the way it appears in source, for trace descriptions.
     */
    public static function describe(?Operand $operand): string
    {
        if ($operand === null) {
            return 'value';
        }

        $name = self::variableName($operand);

        if ($name !== null) {
            return '$' . $name;
        }

        $literal = self::literalValue($operand);

        if (is_string($literal)) {
            return "'" . (strlen($literal) > 32 ? substr($literal, 0, 29) . '...' : $literal) . "'";
        }

        if ($literal !== null) {
            return var_export($literal, true);
        }

        return 'value';
    }

    /**
     * Every operand an op reads or writes, for generic traversal.
     *
     * `getVariableNames()` reports the operand-holding property names; some are
     * arrays, some are nullable, so the enumeration has to be defensive.
     *
     * @return list<Operand>
     */
    public static function operandsOf(Op $op): array
    {
        $operands = [];

        foreach ($op->getVariableNames() as $property) {
            if (! is_string($property)) {
                continue;
            }

            $value = self::readProperty($op, $property);

            if ($value instanceof Operand) {
                $operands[] = $value;

                continue;
            }

            if (! is_array($value)) {
                continue;
            }

            foreach ($value as $item) {
                if ($item instanceof Operand) {
                    $operands[] = $item;
                }
            }
        }

        return $operands;
    }

    /**
     * Read a named operand property from an op.
     *
     * php-cfg has no accessor for this: `getVariableNames()` hands back
     * property names and expects the caller to read them. Isolated here so the
     * dynamic access has exactly one home. See docs/php-cfg-api-notes.md.
     */
    private static function readProperty(Op $op, string $property): mixed
    {
        /** @var array<string, mixed> $vars */
        $vars = get_object_vars($op);

        return $vars[$property] ?? null;
    }
}
