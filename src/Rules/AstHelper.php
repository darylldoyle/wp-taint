<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Small AST reads the structural rules share.
 */
final class AstHelper
{
    /**
     * @param list<Node>          $ast
     * @param class-string<Node>  $class
     *
     * @return list<Node>
     */
    public static function findAll(array $ast, string $class): array
    {
        /** @var list<Node> $found */
        $found = (new NodeFinder())->findInstanceOf($ast, $class);

        return $found;
    }

    /**
     * The lowercase name of a called function, when it is a static name.
     */
    public static function functionName(Node\Expr\FuncCall $call): ?string
    {
        if (! $call->name instanceof Node\Name) {
            return null;
        }

        return strtolower(ltrim($call->name->toString(), '\\'));
    }

    public static function stringValue(?Node $node): ?string
    {
        return $node instanceof Node\Scalar\String_ ? $node->value : null;
    }

    /**
     * Argument at a position, skipping named arguments we cannot order.
     */
    public static function argument(
        Node\Expr\FuncCall|Node\Expr\MethodCall|Node\Expr\StaticCall $call,
        int $index,
    ): ?Node\Expr {
        $args = $call->getArgs();

        return $args[$index]->value ?? null;
    }

    /**
     * Look up a key in an array literal.
     */
    public static function arrayItem(Node\Expr\Array_ $array, string $key): ?Node\Expr
    {
        foreach ($array->items as $item) {
            if ($item === null || $item->key === null) {
                continue;
            }

            if (self::stringValue($item->key) === $key) {
                return $item->value;
            }
        }

        return null;
    }

    public static function hasArrayKey(Node\Expr\Array_ $array, string $key): bool
    {
        return self::arrayItem($array, $key) !== null;
    }

    /**
     * True when the array literal has any dynamic key we cannot read, in which
     * case "the key is missing" is not a safe conclusion.
     */
    public static function hasDynamicKeys(Node\Expr\Array_ $array): bool
    {
        foreach ($array->items as $item) {
            if ($item === null) {
                continue;
            }

            if ($item->unpack) {
                return true;
            }

            if ($item->key !== null && self::stringValue($item->key) === null) {
                return true;
            }
        }

        return false;
    }
}
