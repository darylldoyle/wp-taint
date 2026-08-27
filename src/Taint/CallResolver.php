<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Turns a call op into something the analyser can look up.
 *
 * Direct calls, static calls and method calls on a receiver whose class is
 * statically obvious all resolve. Everything else is left unresolved and marked
 * imprecise, rather than guessed at.
 */
final class CallResolver
{
    /**
     * Receiver variable names that are conventionally the WordPress database
     * handle. `$wpdb` is a global; the others are the two names plugins almost
     * universally use when they stash it on an object.
     */
    private const WPDB_RECEIVER_NAMES = ['wpdb', 'db'];

    public function __construct(
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
    ) {
    }

    public function resolve(Op $op, FunctionContext $context, ClassTypeMap $types): ?CallTarget
    {
        return match (true) {
            $op instanceof Op\Expr\FuncCall => $this->resolveFunctionCall($op),
            $op instanceof Op\Expr\NsFuncCall => $this->resolveNamespacedCall($op),
            $op instanceof Op\Expr\MethodCall => $this->resolveMethodCall($op, $context, $types),
            $op instanceof Op\Expr\StaticCall => $this->resolveStaticCall($op, $context),
            $op instanceof Op\Expr\New_ => $this->resolveConstructorCall($op),
            default => null,
        };
    }

    private function resolveFunctionCall(Op\Expr\FuncCall $op): CallTarget
    {
        $name = OperandHelper::literalString($op->name);
        $arguments = $this->arguments($op->args);

        if ($name !== null) {
            return $this->targetForFunctionName($name, $arguments);
        }

        // `$render($x)` where `$render` holds a closure declared in this file.
        $closure = $this->closureBehind($op->name);

        if ($closure !== null) {
            return CallTarget::resolved($arguments, null, $closure->key, $closure->displayName . '()');
        }

        return CallTarget::dynamic($arguments, OperandHelper::describe($op->name) . '()');
    }

    /**
     * Follow an operand back to a closure or arrow function declaration.
     *
     * Assignments are transparent, so `$a = fn () => ...; $b = $a; $b();`
     * resolves. Anything that leaves the chain — a parameter, a property, a
     * call result — stops the walk and the call stays dynamic.
     */
    private function closureBehind(Operand $operand, int $depth = 0): ?FunctionContext
    {
        if ($depth > 8) {
            return null;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->closureBehind($definition->expr, $depth + 1);
        }

        if ($definition instanceof Op\CallableOp) {
            return $this->functions->forFunc($definition->getFunc());
        }

        return null;
    }

    private function resolveNamespacedCall(Op\Expr\NsFuncCall $op): CallTarget
    {
        $arguments = $this->arguments($op->args);

        // A namespaced call falls back to the global function when the
        // namespaced one does not exist, so both names have to be tried. The
        // namespaced name wins when the scanned code actually defines it.
        $namespaced = OperandHelper::literalString($op->nsName);
        $global = OperandHelper::literalString($op->name);

        if ($namespaced !== null && $this->functions->has($namespaced)) {
            return CallTarget::resolved(
                $arguments,
                Matcher::function($namespaced),
                strtolower($namespaced),
                $namespaced . '()',
            );
        }

        if ($global !== null) {
            return $this->targetForFunctionName($global, $arguments);
        }

        if ($namespaced !== null) {
            return $this->targetForFunctionName($namespaced, $arguments);
        }

        return CallTarget::dynamic($arguments, 'unknown()');
    }

    /**
     * @param list<Operand> $arguments
     */
    private function targetForFunctionName(string $name, array $arguments): CallTarget
    {
        $matcher = Matcher::function($name);
        $userKey = $this->functions->has($name) ? strtolower(ltrim($name, '\\')) : null;

        return CallTarget::resolved($arguments, $matcher, $userKey, $name . '()');
    }

    private function resolveMethodCall(
        Op\Expr\MethodCall $op,
        FunctionContext $context,
        ClassTypeMap $types,
    ): CallTarget {
        $arguments = $this->arguments($op->args);
        $method = OperandHelper::literalString($op->name);

        if ($method === null) {
            return CallTarget::dynamic($arguments, OperandHelper::describe($op->var) . '->{dynamic}()');
        }

        $class = $this->receiverClass($op->var, $context, $types);

        if ($class !== null) {
            return CallTarget::resolved(
                $arguments,
                Matcher::method($class, $method),
                $this->functions->has($class . '::' . $method) ? strtolower($class . '::' . $method) : null,
                $class . '::' . $method . '()',
            );
        }

        return $this->resolveMethodByNameOnly($arguments, $op, $method);
    }

    /**
     * Last resort for a method call on a receiver of unknown type.
     *
     * Only used when the scanned code does not itself declare a method of that
     * name. `$request->get_param()` is worth resolving to `WP_REST_Request`;
     * `$repo->query()` on a plugin's own repository class is not worth
     * guessing as `wpdb::query()`, and that guess would be a false positive
     * with a critical severity attached to it.
     */
    /**
     * @param list<Operand> $arguments
     */
    private function resolveMethodByNameOnly(array $arguments, Op\Expr\MethodCall $op, string $method): CallTarget
    {
        if ($this->functions->definesMethodNamed($method)) {
            $unique = $this->functions->uniqueMethodNamed($method);

            if ($unique !== null) {
                return CallTarget::resolved($arguments, null, $unique->key, $unique->displayName . '()');
            }

            return CallTarget::dynamic($arguments, OperandHelper::describe($op->var) . '->' . $method . '()');
        }

        foreach ($this->registryMethodClassesFor($method) as $class) {
            return CallTarget::resolved(
                $arguments,
                Matcher::method($class, $method),
                null,
                $class . '::' . $method . '()',
            );
        }

        return CallTarget::dynamic($arguments, OperandHelper::describe($op->var) . '->' . $method . '()');
    }

    /**
     * Classes in the catalogue that declare a method of this name.
     *
     * Returns more than one only if the catalogue itself is ambiguous, in which
     * case the caller declines to guess.
     *
     * @return list<string>
     */
    private function registryMethodClassesFor(string $method): array
    {
        $needle = '::' . strtolower($method);
        $classes = [];

        foreach (
            [
            $this->registry->sources(),
            $this->registry->sanitizers(),
            $this->registry->propagators(),
            $this->registry->sinks(),
            $this->registry->safeCalls(),
            ] as $entries
        ) {
            foreach (array_keys($entries) as $key) {
                if (! str_starts_with($key, 'method:') || ! str_ends_with($key, $needle)) {
                    continue;
                }

                $class = substr($key, strlen('method:'), -strlen($needle));

                if ($class !== '' && ! in_array($class, $classes, true)) {
                    $classes[] = $class;
                }
            }
        }

        return count($classes) === 1 ? $classes : [];
    }

    private function resolveStaticCall(Op\Expr\StaticCall $op, FunctionContext $context): CallTarget
    {
        $arguments = $this->arguments($op->args);
        $method = OperandHelper::literalString($op->name);
        $class = OperandHelper::literalString($op->class);

        if ($class !== null && in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
            $class = $context->className;
        }

        if ($method === null || $class === null) {
            return CallTarget::dynamic($arguments, ($class ?? 'unknown') . '::{dynamic}()');
        }

        $userKey = $this->functions->has($class . '::' . $method) ? strtolower($class . '::' . $method) : null;

        return CallTarget::resolved(
            $arguments,
            Matcher::staticMethod($class, $method),
            $userKey,
            $class . '::' . $method . '()',
        );
    }

    private function resolveConstructorCall(Op\Expr\New_ $op): CallTarget
    {
        $arguments = $this->arguments($op->args);
        $class = OperandHelper::literalString($op->class);

        if ($class === null) {
            return CallTarget::dynamic($arguments, 'new {dynamic}()');
        }

        $userKey = $this->functions->has($class . '::__construct') ? strtolower($class . '::__construct') : null;

        return CallTarget::resolved(
            $arguments,
            Matcher::method($class, '__construct'),
            $userKey,
            'new ' . $class . '()',
        );
    }

    /**
     * The class of a method call's receiver, when it is statically obvious.
     */
    private function receiverClass(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
        $name = OperandHelper::variableName($receiver);

        if ($name === 'this') {
            return $context->className;
        }

        if ($name !== null && in_array(strtolower($name), self::WPDB_RECEIVER_NAMES, true)) {
            return 'wpdb';
        }

        $tracked = $types->classOf($receiver);

        if ($tracked !== null) {
            return $tracked;
        }

        // `$this->wpdb->query()` and `$this->db->query()`: the receiver is a
        // property fetch, and these two property names are the near-universal
        // convention for stashing the database handle.
        $definition = OperandHelper::definingOp($receiver);

        if ($definition instanceof Op\Expr\PropertyFetch) {
            $property = OperandHelper::literalString($definition->name);

            if ($property !== null && in_array(strtolower($property), self::WPDB_RECEIVER_NAMES, true)) {
                return 'wpdb';
            }

            return $property === null
                ? null
                : $types->classOfProperty($this->receiverClass($definition->var, $context, $types), $property);
        }

        return null;
    }

    /**
     * @param array<array-key, mixed> $args
     *
     * @return list<Operand>
     */
    private function arguments(array $args): array
    {
        $operands = [];

        foreach ($args as $arg) {
            if ($arg instanceof Operand) {
                $operands[] = $arg;
            }
        }

        return $operands;
    }
}
