<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Connects `add_action('wp_ajax_x', $callback)` to the body of `$callback`.
 *
 * Handles the four shapes that cover almost all real code: a string function
 * name, `[$this, 'method']`, `[__CLASS__, 'method']` or `[self::class,
 * 'method']`, and an inline closure. Anything else is reported as an unresolved
 * hook rather than skipped, so the coverage gap is visible.
 */
final class HookCallbackResolver
{
    /**
     * @param list<Node> $ast
     */
    public function __construct(private readonly array $ast)
    {
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string}|null
     */
    public function resolve(Node\Expr $callback, ?string $enclosingClass): ?array
    {
        if ($callback instanceof Node\Expr\Closure) {
            return ['stmts' => array_values($callback->stmts), 'description' => 'inline closure'];
        }

        if ($callback instanceof Node\Expr\ArrowFunction) {
            return [
                'stmts' => [new Node\Stmt\Return_($callback->expr)],
                'description' => 'inline arrow function',
            ];
        }

        $name = $callback instanceof Node\Scalar\String_ ? $callback->value : null;

        if ($name !== null) {
            if (str_contains($name, '::')) {
                $parts = explode('::', $name, 2);

                return isset($parts[1]) ? $this->method($parts[0], $parts[1]) : null;
            }

            return $this->function($name);
        }

        if ($callback instanceof Node\Expr\Array_ && count($callback->items) === 2) {
            return $this->arrayCallback($callback, $enclosingClass);
        }

        return null;
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string}|null
     */
    private function arrayCallback(Node\Expr\Array_ $callback, ?string $enclosingClass): ?array
    {
        $items = array_values($callback->items);
        $target = ($items[0] ?? null)?->value;
        $method = ($items[1] ?? null)?->value;

        $methodName = $method instanceof Node\Scalar\String_ ? $method->value : null;

        if ($methodName === null) {
            return null;
        }

        if ($target instanceof Node\Expr\Variable && $target->name === 'this') {
            return $enclosingClass === null ? null : $this->method($enclosingClass, $methodName);
        }

        if ($target instanceof Node\Scalar\String_) {
            return $this->method($target->value, $methodName);
        }

        if ($target instanceof Node\Expr\ClassConstFetch && $target->class instanceof Node\Name) {
            $class = $target->class->toString();

            if (in_array(strtolower($class), ['self', 'static'], true)) {
                $class = $enclosingClass;
            }

            return $class === null ? null : $this->method($class, $methodName);
        }

        if ($target instanceof Node\Expr\ConstFetch && strtolower($target->name->toString()) === '__class__') {
            return $enclosingClass === null ? null : $this->method($enclosingClass, $methodName);
        }

        return null;
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string}|null
     */
    private function function(string $name): ?array
    {
        $needle = strtolower(ltrim($name, '\\'));

        foreach ((new NodeFinder())->findInstanceOf($this->ast, Node\Stmt\Function_::class) as $function) {
            if (! $function instanceof Node\Stmt\Function_) {
                continue;
            }

            $qualified = $function->namespacedName?->toString() ?? $function->name->toString();

            if (
                strtolower(ltrim($qualified, '\\')) !== $needle
                && strtolower($function->name->toString()) !== $needle
            ) {
                continue;
            }

            return ['stmts' => array_values($function->stmts ?? []), 'description' => $name . '()'];
        }

        return null;
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string}|null
     */
    private function method(string $class, string $method): ?array
    {
        $classNeedle = strtolower(ltrim($class, '\\'));
        $methodNeedle = strtolower($method);

        foreach ((new NodeFinder())->findInstanceOf($this->ast, Node\Stmt\ClassLike::class) as $classLike) {
            if (! $classLike instanceof Node\Stmt\ClassLike || $classLike->name === null) {
                continue;
            }

            $names = array_filter(
                [
                    strtolower($classLike->name->toString()),
                    strtolower(ltrim($classLike->namespacedName?->toString() ?? '', '\\')),
                ],
                static fn (string $name): bool => $name !== '',
            );

            if (! in_array($classNeedle, $names, true)) {
                continue;
            }

            foreach ($classLike->getMethods() as $classMethod) {
                if (strtolower($classMethod->name->toString()) !== $methodNeedle) {
                    continue;
                }

                return [
                    'stmts' => array_values($classMethod->stmts ?? []),
                    'description' => $class . '::' . $method . '()',
                ];
            }
        }

        return null;
    }
}
