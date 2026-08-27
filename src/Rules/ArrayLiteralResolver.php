<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Follows an expression back to the array literal behind it.
 *
 * `register_rest_route()` is very often written with its options somewhere
 * else:
 *
 * ```php
 * $args = array( 'methods' => 'POST', 'callback' => …, 'permission_callback' => … );
 * register_rest_route( 'acme/v1', '/thing', $args );
 *
 * register_rest_route( 'acme/v1', '/thing', $this->route_args() );
 * ```
 *
 * Both were counted as unresolved and skipped, which meant the most
 * safety-critical rule in the tool quietly declined to look at a large share of
 * the routes in the corpus.
 *
 * This is deliberately a constant fold and not a dataflow analysis. A variable
 * assigned exactly once from a literal, or a function whose only `return` is a
 * literal, resolves. Anything built conditionally, appended to, or passed
 * through a filter does not, and stays unresolved — the honest answer.
 */
final class ArrayLiteralResolver
{
    /**
     * @param list<Node> $ast
     */
    public function __construct(private readonly array $ast)
    {
    }

    public function resolve(Node\Expr $expression, ?Node\FunctionLike $scope, int $depth = 0): ?Node\Expr\Array_
    {
        if ($expression instanceof Node\Expr\Array_) {
            return $expression;
        }

        if ($depth > 3) {
            return null;
        }

        if ($expression instanceof Node\Expr\Variable && is_string($expression->name)) {
            return $this->fromVariable($expression->name, $scope, $depth);
        }

        if ($expression instanceof Node\Expr\MethodCall && $expression->name instanceof Node\Identifier) {
            return $this->fromReturn($this->methodBody($expression->name->toString()), $depth);
        }

        if ($expression instanceof Node\Expr\StaticCall && $expression->name instanceof Node\Identifier) {
            return $this->fromReturn($this->methodBody($expression->name->toString()), $depth);
        }

        if ($expression instanceof Node\Expr\FuncCall && $expression->name instanceof Node\Name) {
            return $this->fromReturn($this->functionBody($expression->name->toString()), $depth);
        }

        return null;
    }

    /**
     * A variable assigned exactly once, from a literal.
     *
     * Once is the whole test. Two assignments means the value at the call site
     * depends on control flow, and picking either would be a guess in the one
     * rule where a wrong answer is an authorization bypass reported or missed.
     */
    private function fromVariable(string $name, ?Node\FunctionLike $scope, int $depth): ?Node\Expr\Array_
    {
        $search = $scope?->getStmts() ?? $this->ast;
        $assignments = [];

        foreach ((new NodeFinder())->findInstanceOf($search, Node\Expr\Assign::class) as $assign) {
            if (! $assign instanceof Node\Expr\Assign) {
                continue;
            }

            if ($assign->var instanceof Node\Expr\Variable && $assign->var->name === $name) {
                $assignments[] = $assign->expr;
            }
        }

        // An append or an element write means the literal is not the whole
        // story, so the fold is off.
        foreach ((new NodeFinder())->findInstanceOf($search, Node\Expr\ArrayDimFetch::class) as $fetch) {
            if (
                $fetch instanceof Node\Expr\ArrayDimFetch
                && $fetch->var instanceof Node\Expr\Variable
                && $fetch->var->name === $name
            ) {
                return null;
            }
        }

        return count($assignments) === 1 ? $this->resolve($assignments[0], $scope, $depth + 1) : null;
    }

    /**
     * A body whose only `return` hands back a literal.
     *
     * @param list<Node\Stmt>|null $stmts
     */
    private function fromReturn(?array $stmts, int $depth): ?Node\Expr\Array_
    {
        if ($stmts === null) {
            return null;
        }

        $returns = [];

        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Stmt\Return_::class) as $return) {
            if ($return instanceof Node\Stmt\Return_ && $return->expr !== null) {
                $returns[] = $return->expr;
            }
        }

        return count($returns) === 1 ? $this->resolve($returns[0], null, $depth + 1) : null;
    }

    /**
     * @return list<Node\Stmt>|null
     */
    private function methodBody(string $method): ?array
    {
        $needle = strtolower($method);
        $found = null;

        foreach ((new NodeFinder())->findInstanceOf($this->ast, Node\Stmt\ClassMethod::class) as $classMethod) {
            if (! $classMethod instanceof Node\Stmt\ClassMethod) {
                continue;
            }

            if (strtolower($classMethod->name->toString()) !== $needle) {
                continue;
            }

            // Two methods of that name in one file: the receiver decides which,
            // and this resolver does not track receivers.
            if ($found !== null) {
                return null;
            }

            $found = array_values($classMethod->stmts ?? []);
        }

        return $found;
    }

    /**
     * @return list<Node\Stmt>|null
     */
    private function functionBody(string $name): ?array
    {
        $needle = strtolower(ltrim($name, '\\'));

        foreach ((new NodeFinder())->findInstanceOf($this->ast, Node\Stmt\Function_::class) as $function) {
            if (! $function instanceof Node\Stmt\Function_) {
                continue;
            }

            $qualified = strtolower(ltrim($function->namespacedName?->toString() ?? '', '\\'));

            if ($qualified !== $needle && strtolower($function->name->toString()) !== $needle) {
                continue;
            }

            return array_values($function->stmts ?? []);
        }

        return null;
    }
}
