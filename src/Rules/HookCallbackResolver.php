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
     * A registration made through the plugin's own wrapper.
     *
     * Boilerplate-generated plugins do not call `add_action()` where you can
     * see it. They collect registrations on a loader and replay them later, and
     * three arg layouts cover everything the corpus actually contains:
     *
     * ```php
     * $this->loader->add_action( 'wp_ajax_x', $component, 'method' );  // WPPB
     * $this->add_action( 'wp_ajax_x', array( $this, 'method' ) );      // wrapped array
     * $this->add_action( 'wp_ajax_x', 'method' );                      // method on $this
     * ```
     *
     * Eight of the fifty corpus plugins register hooks this way, and until now
     * none of those registrations existed as far as this engine was concerned —
     * not resolved, not reported unresolved, simply absent. A clean
     * authorization report on a boilerplate plugin meant the rules never ran.
     *
     * Matching on the method name alone, whatever the receiver, is a heuristic:
     * every plugin names its loader something different, and a method called
     * `add_action` that is not a hook registration would be perverse.
     *
     * @param array<array-key, Node\Arg> $args
     *
     * @return array{stmts: list<Node\Stmt>, description: string, key: string|null}|null
     */
    public function resolveWrapped(array $args, ?string $enclosingClass, bool $receiverIsThis): ?array
    {
        $args = array_values($args);
        $first = ($args[1] ?? null)?->value;

        if ($first === null) {
            return null;
        }

        // `$loader->add_action( $hook, $component, 'method' )`: the callback is
        // split across two arguments.
        $second = ($args[2] ?? null)?->value;

        if ($second instanceof Node\Scalar\String_ && ! $first instanceof Node\Scalar\String_) {
            $class = $this->receiverClass($first, $enclosingClass);

            return $class === null ? null : $this->method($class, $second->value);
        }

        // `$this->add_action( $hook, 'method' )`: a bare method name on the
        // enclosing class, which is only meaningful when the receiver is $this.
        if (
            $first instanceof Node\Scalar\String_
            && $receiverIsThis
            && ! str_contains($first->value, '::')
            && $enclosingClass !== null
        ) {
            return $this->method($enclosingClass, $first->value);
        }

        return $this->resolve($first, $enclosingClass);
    }

    /**
     * The class of a receiver passed as a callback component.
     *
     * `$this` is the enclosing class. Otherwise: the boilerplate builds the
     * component immediately before registering it —
     *
     * ```php
     * $plugin_admin = new Plugin_Name_Admin( $this->get_plugin_name() );
     * $this->loader->add_action( 'wp_ajax_x', $plugin_admin, 'handler' );
     * ```
     *
     * — so the one `new` in the same file naming that variable answers it. Two
     * different classes assigned to the same name means the answer depends on
     * control flow, and a wrong class here would credit the wrong method body
     * for an authorization check, so it gives up instead.
     */
    private function receiverClass(Node\Expr $receiver, ?string $enclosingClass): ?string
    {
        // `$this->admin` — a component stashed on a property. Its class is in
        // this file three ways: a typed declaration, a promoted constructor
        // parameter, or a `$this->admin = new Acme_Admin()` in the
        // constructor. Boilerplate that registers through a loader keeps the
        // component and the registration in one class, so the same file's AST
        // is where the answer lives.
        if (
            $receiver instanceof Node\Expr\PropertyFetch
            && $receiver->var instanceof Node\Expr\Variable
            && $receiver->var->name === 'this'
            && $receiver->name instanceof Node\Identifier
        ) {
            return $this->propertyClass($receiver->name->toString());
        }

        if (! $receiver instanceof Node\Expr\Variable || ! is_string($receiver->name)) {
            return null;
        }

        if ($receiver->name === 'this') {
            return $enclosingClass;
        }

        $found = [];

        foreach ((new NodeFinder())->findInstanceOf($this->ast, Node\Expr\Assign::class) as $assign) {
            if (! $assign instanceof Node\Expr\Assign) {
                continue;
            }

            if (! $assign->var instanceof Node\Expr\Variable || $assign->var->name !== $receiver->name) {
                continue;
            }

            if ($assign->expr instanceof Node\Expr\New_ && $assign->expr->class instanceof Node\Name) {
                $found[$assign->expr->class->toString()] = true;
            }
        }

        return count($found) === 1 ? (string) array_key_first($found) : null;
    }

    /**
     * The class a property holds, read from this file's declarations.
     *
     * The same three signals {@see \Enshrined\WpTaint\Taint\DeclaredTypes}
     * indexes project-wide, limited to one AST because that is all a
     * structural rule holds. Two classes for one property name is ambiguous
     * and gives up, for the same reason receiverClass() does: a wrong class
     * credits the wrong method body for an authorization check.
     */
    private function propertyClass(string $property): ?string
    {
        $found = [];
        $finder = new NodeFinder();

        foreach ($finder->findInstanceOf($this->ast, Node\Stmt\Property::class) as $declaration) {
            if (! $declaration instanceof Node\Stmt\Property || ! $declaration->type instanceof Node\Name) {
                continue;
            }

            foreach ($declaration->props as $declared) {
                if ($declared->name->toString() === $property) {
                    $found[$declaration->type->toString()] = true;
                }
            }
        }

        foreach ($finder->findInstanceOf($this->ast, Node\Param::class) as $parameter) {
            if (
                ! $parameter instanceof Node\Param
                || $parameter->flags === 0
                || ! $parameter->type instanceof Node\Name
                || ! $parameter->var instanceof Node\Expr\Variable
                || $parameter->var->name !== $property
            ) {
                continue;
            }

            $found[$parameter->type->toString()] = true;
        }

        foreach ($finder->findInstanceOf($this->ast, Node\Expr\Assign::class) as $assign) {
            if (
                ! $assign instanceof Node\Expr\Assign
                || ! $assign->var instanceof Node\Expr\PropertyFetch
                || ! $assign->var->name instanceof Node\Identifier
                || $assign->var->name->toString() !== $property
                || ! $assign->expr instanceof Node\Expr\New_
                || ! $assign->expr->class instanceof Node\Name
            ) {
                continue;
            }

            $found[$assign->expr->class->toString()] = true;
        }

        return count($found) === 1 ? (string) array_key_first($found) : null;
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string, key: string|null}|null
     */
    public function resolve(Node\Expr $callback, ?string $enclosingClass): ?array
    {
        if ($callback instanceof Node\Expr\Closure) {
            return ['stmts' => array_values($callback->stmts), 'description' => 'inline closure', 'key' => null];
        }

        if ($callback instanceof Node\Expr\ArrowFunction) {
            return [
                'stmts' => [new Node\Stmt\Return_($callback->expr)],
                'description' => 'inline arrow function',
                'key' => null,
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
     * @return array{stmts: list<Node\Stmt>, description: string, key: string|null}|null
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
     * @return array{stmts: list<Node\Stmt>, description: string, key: string|null}|null
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

            return [
                'stmts' => array_values($function->stmts ?? []),
                'description' => $name . '()',
                'key' => strtolower(ltrim($qualified, '\\')),
            ];
        }

        return null;
    }

    /**
     * @return array{stmts: list<Node\Stmt>, description: string, key: string|null}|null
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

                $qualified = $classLike->namespacedName?->toString() ?? $classLike->name->toString();

                return [
                    'stmts' => array_values($classMethod->stmts ?? []),
                    'description' => $class . '::' . $method . '()',
                    'key' => strtolower(ltrim($qualified, '\\') . '::' . $method),
                ];
            }
        }

        return null;
    }
}
