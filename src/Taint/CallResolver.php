<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Hooks\HookGraph;
use Enshrined\WpTaint\Registry\Dispatcher;
use Enshrined\WpTaint\Registry\DispatchMode;
use Enshrined\WpTaint\Registry\DispatchReturn;
use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Turns a call op into something the analyser can look up.
 *
 * Direct calls, static calls and method calls on a receiver whose class is
 * statically obvious all resolve. So do calls through a variable holding a
 * callable, and calls made on your behalf by a dispatcher such as
 * `call_user_func()`.
 *
 * Everything left over is unresolved and marked imprecise, rather than guessed
 * at. What happens to an unresolved call is the caller's decision, not this
 * class's — see `--dynamic-calls`.
 */
final class CallResolver
{
    /**
     * Receiver variable names that are conventionally the WordPress database
     * handle. `$wpdb` is a global; the others are the two names plugins almost
     * universally use when they stash it on an object.
     */
    public function __construct(
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
        private readonly CallableResolver $callables,
        private readonly ValueResolver $values,
        private readonly ReceiverResolver $receivers,
        private readonly ?HookGraph $hooks = null,
    ) {
    }

    /**
     * Every callee a call op can reach.
     *
     * Usually one. Several when a callable variable holds a different name on
     * each side of a branch, or when a dispatcher's callable resolves that way.
     * None when the op is not a call at all.
     *
     * @return list<CallTarget>
     */
    public function resolveAll(Op $op, FunctionContext $context, ClassTypeMap $types): array
    {
        $direct = $this->resolve($op, $context, $types);

        if ($direct === null) {
            return [];
        }

        // `$callback( $x )` where `$callback` holds a name rather than a
        // closure. The direct resolver cannot see through it, but the value
        // resolver can.
        if ($direct->dynamic && $op instanceof Op\Expr\FuncCall) {
            $indirect = $this->callables->resolve(
                $op->name,
                $direct->arguments,
                $context,
                $types,
                $this->receivers,
            );

            if ($indirect !== []) {
                return $indirect;
            }
        }

        // `new $handler()` where `$handler` holds a class name.
        if ($direct->dynamic && $op instanceof Op\Expr\New_) {
            $constructed = $this->constructorsFor($op->class, $direct->arguments);

            if ($constructed !== []) {
                return $constructed;
            }
        }

        return $this->withDispatched($direct, $context, $types);
    }

    /**
     * A call, plus whatever it runs on your behalf.
     *
     * The dispatcher's own catalogue entry does not simply step aside. Whether
     * it stays depends on what the dispatcher does with its callee's return:
     * `call_user_func()` hands it straight back, so the callee replaces it,
     * while `array_filter()` returns a subset of its *input*, so its propagator
     * entry is the one that decides the result and the predicate is analysed
     * only for its sinks.
     *
     * @return list<CallTarget>
     */
    private function withDispatched(CallTarget $direct, FunctionContext $context, ClassTypeMap $types): array
    {
        $matcher = $direct->matcher;
        $dispatcher = $matcher === null ? null : $this->registry->dispatcher($matcher);

        if ($dispatcher === null) {
            return [$direct];
        }

        $dispatched = $dispatcher->hook
            ? $this->dispatchedByHook($direct, $dispatcher)
            : $this->dispatched($direct, $dispatcher, $context, $types);

        if ($dispatched === []) {
            // A hook with nothing registered on it returns the value it was
            // handed, and that is a *known* answer rather than a failure to
            // resolve — the catalogue's own propagator entry states it. Falling
            // through to the dynamic case would turn every dispatch on a hook
            // this scan happens not to see into an unresolved call.
            if ($dispatcher->hook) {
                return [$direct];
            }

            // For everything else an empty set means the callable could not be
            // pinned down. When the dispatcher hands its callee's return back,
            // that return is genuinely unknown and the call is dynamic —
            // reporting it as an unmodelled function would lose the flow
            // without even marking it imprecise.
            return $dispatcher->returns === DispatchReturn::Own
                ? [$direct]
                : [CallTarget::dynamic($direct->arguments, $direct->name())];
        }

        $mode = match ($dispatcher->returns) {
            DispatchReturn::Callee => CallResultMode::Value,
            DispatchReturn::CalleeArray => CallResultMode::Container,
            DispatchReturn::Own => CallResultMode::Discard,
        };

        $targets = array_map(
            static fn (CallTarget $target): CallTarget => $target->returningTo($mode),
            $dispatched,
        );

        // `array_filter()` and friends still need their own entry to run: it is
        // what puts the input array's taint on the result.
        return $dispatcher->returns === DispatchReturn::Own ? [$direct, ...$targets] : $targets;
    }

    /**
     * The callbacks a hook dispatch runs.
     *
     * `apply_filters( 'the_content', $html )` is a call to every callback
     * registered on `the_content`, and until the hook graph existed it was a
     * call to nothing at all. A filter callback reading `$_GET` could taint a
     * value the engine believed was clean; an action's arguments never reached
     * the sinks inside its callbacks.
     *
     * @return list<CallTarget>
     */
    private function dispatchedByHook(CallTarget $call, Dispatcher $dispatcher): array
    {
        if ($this->hooks === null) {
            return [];
        }

        $name = $call->argument($dispatcher->callable);

        if ($name === null) {
            return [];
        }

        $arguments = $this->calleeArguments($call, $dispatcher);
        $targets = [];

        foreach ($this->values->strings($name) as $hook) {
            foreach ($this->hooks->targetsFor($hook) as $target) {
                $targets[] = $target->withArguments($arguments);
            }
        }

        return $targets;
    }

    /**
     * `new $class()` for every class name the operand can hold.
     *
     * @param list<Operand> $arguments
     *
     * @return list<CallTarget>
     */
    private function constructorsFor(Operand $class, array $arguments): array
    {
        $targets = [];

        foreach ($this->values->strings($class) as $name) {
            $name = ltrim($name, '\\');

            if ($name === '') {
                continue;
            }

            $key = $this->functions->resolveMethodKey($name, '__construct');
            $matcher = Matcher::method($name, '__construct');

            // A class name nobody can find a definition for leaves the call
            // dynamic, rather than resolving it to nothing and reporting clean.
            if ($key === null && ! $this->registry->knows($matcher)) {
                continue;
            }

            $targets[] = CallTarget::resolved(
                $arguments,
                $matcher,
                $key,
                'new ' . $name . '()',
            );
        }

        return $targets;
    }

    /**
     * The callees a dispatcher such as `call_user_func()` runs.
     *
     * Empty when the callable argument could not be resolved.
     *
     * @return list<CallTarget>
     */
    private function dispatched(
        CallTarget $call,
        Dispatcher $dispatcher,
        FunctionContext $context,
        ClassTypeMap $types,
    ): array {
        $callable = $call->argument($dispatcher->callable);

        if ($callable === null) {
            return [];
        }

        return $this->callables->resolve(
            $callable,
            $this->calleeArguments($call, $dispatcher),
            $context,
            $types,
            $this->receivers,
        );
    }

    /**
     * The arguments the dispatcher hands the callee.
     *
     * @return list<Operand>
     */
    private function calleeArguments(CallTarget $call, Dispatcher $dispatcher): array
    {
        $arguments = [];

        for ($index = $dispatcher->argumentStart; $index < $call->argumentCount(); $index++) {
            if ($index === $dispatcher->callable) {
                continue;
            }

            $argument = $call->argument($index);

            if ($argument === null) {
                continue;
            }

            $arguments[] = $argument;

            // `spread` and `elements` both take a single array argument and
            // unpack it. SSA gives that array one operand, so there is nothing
            // finer to hand over: the callee's first parameter receives it, and
            // the analysis reads its element taint from there.
            if ($dispatcher->mode !== DispatchMode::Rest) {
                break;
            }
        }

        return $arguments;
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
        $closure = $this->callables->closureBehind($op->name);

        if ($closure !== null) {
            return CallTarget::resolved($arguments, null, $closure->key, $closure->displayName . '()');
        }

        return CallTarget::dynamic($arguments, OperandHelper::describe($op->name) . '()');
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

        // A computed name that folds to exactly one string is that method.
        //
        //     $m = 'verify';
        //     $this->$m();
        //
        // The value resolver already answers this for hook names and class
        // names; not asking it here made the call unresolvable, which walked an
        // AJAX handler's capability check straight past the authorization rule
        // and reported a handler that checks as one that does not. Several
        // answers stay dynamic: picking one would be a guess, and the union of
        // effects belongs to the callable path, not this one.
        if ($method === null) {
            $names = $this->values->strings($op->name);
            $method = count($names) === 1 ? $names[0] : null;
        }

        if ($method === null) {
            return CallTarget::dynamic($arguments, OperandHelper::describe($op->var) . '->{dynamic}()');
        }

        $class = $this->receiverClass($op->var, $context, $types);

        if ($class !== null) {
            return CallTarget::resolved(
                $arguments,
                Matcher::method($class, $method),
                $this->functions->resolveMethodKey($class, $method),
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

        if ($class !== null && in_array(strtolower($class), ['self', 'static'], true)) {
            $class = $context->className;
        }

        // `parent::` starts the lookup one level up, or PHP's semantics are
        // lost twice over: `parent::render()` inside an override would resolve
        // to the override itself, and a summary of `render()` that calls
        // `parent::render()` would contain a call to its own key. A parent the
        // scan has no declaration for falls back to the calling class, which is
        // the old behaviour: conservative, and right whenever the method is not
        // overridden.
        if ($class !== null && strtolower($class) === 'parent') {
            $class = $context->className === null
                ? null
                : ($this->functions->classHierarchy()->parentOf($context->className) ?? $context->className);
        }

        if ($method === null || $class === null) {
            return CallTarget::dynamic($arguments, ($class ?? 'unknown') . '::{dynamic}()');
        }

        return CallTarget::resolved(
            $arguments,
            Matcher::staticMethod($class, $method),
            $this->functions->resolveMethodKey($class, $method),
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

        return CallTarget::resolved(
            $arguments,
            Matcher::method($class, '__construct'),
            $this->functions->resolveMethodKey($class, '__construct'),
            'new ' . $class . '()',
        );
    }

    private function receiverClass(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
        return $this->receivers->classOf($receiver, $context, $types);
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
