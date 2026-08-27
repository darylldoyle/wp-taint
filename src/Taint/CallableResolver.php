<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Turns a PHP callable value into the call targets it can reach.
 *
 * Every form the language accepts:
 *
 * | Written as | Resolves to |
 * | --- | --- |
 * | `'wp_kses_post'` | that function |
 * | `'Acme\Renderer::render'` | that static method |
 * | `array( $this, 'render' )` | a method on the receiver's class |
 * | `array( 'Acme_Renderer', 'render' )` | that static method |
 * | `array( $obj, 'render' )` | a method, if the receiver's class is known |
 * | a closure or arrow function | the declared body |
 * | `$obj` alone | its `__invoke`, if the class is known |
 *
 * A callable that resolves to several names — a variable assigned one string on
 * each side of a branch — returns several targets. The caller unions their
 * effects rather than choosing one, which is the only sound answer.
 *
 * An empty result means the callable could not be pinned down. That is a real
 * answer and the caller has to handle it: silently treating it as "no targets,
 * therefore nothing happens" is how a taint analyser loses a flow.
 *
 * A name nobody can find a body for counts as *not* pinned down. Resolving
 * `'render_a'` to a function that exists in neither the catalogue nor the
 * scanned code and then reporting it clean would be worse than admitting
 * defeat: the flow would disappear without even being marked imprecise.
 */
final class CallableResolver
{
    public function __construct(
        private readonly Registry $registry,
        private readonly UserFunctionTable $functions,
        private readonly ValueResolver $values,
    ) {
    }

    /**
     * Every function or method the callable operand can reach.
     *
     * @param list<Operand> $arguments the arguments the callee will receive
     *
     * @return list<CallTarget>
     */
    public function resolve(
        Operand $callable,
        array $arguments,
        FunctionContext $context,
        ClassTypeMap $types,
        ReceiverResolver $receivers,
    ): array {
        $targets = [];

        foreach ($this->values->strings($callable) as $name) {
            $target = $this->fromString($name, $arguments);

            if ($target !== null) {
                $targets[] = $target;
            }
        }

        $pair = $this->values->callableArray($callable);

        if ($pair !== null) {
            foreach ($this->fromPair($pair[0], $pair[1], $arguments, $context, $types, $receivers) as $target) {
                $targets[] = $target;
            }
        }

        $closure = $this->closureBehind($callable);

        if ($closure !== null) {
            $targets[] = CallTarget::resolved($arguments, null, $closure->key, $closure->displayName . '()');
        }

        $invokable = $this->invokableBehind($callable, $context, $types, $receivers);

        if ($invokable !== null) {
            $targets[] = $invokable->withArguments($arguments);
        }

        return self::unique($targets);
    }

    /**
     * `'strlen'` and `'Acme\Renderer::render'`.
     *
     * @param list<Operand> $arguments
     */
    private function fromString(string $name, array $arguments): ?CallTarget
    {
        $name = ltrim($name, '\\');

        if ($name === '') {
            return null;
        }

        if (! str_contains($name, '::')) {
            return $this->target($arguments, Matcher::function($name), $name, $name . '()');
        }

        $parts = explode('::', $name, 2);

        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }

        [$class, $method] = $parts;

        return $this->target(
            $arguments,
            Matcher::staticMethod($class, $method),
            $class . '::' . $method,
            $class . '::' . $method . '()',
        );
    }

    /**
     * A target, but only if something can actually say what the callee does.
     *
     * @param list<Operand> $arguments
     */
    private function target(array $arguments, Matcher $matcher, string $key, string $display): ?CallTarget
    {
        $known = $this->functions->has($key);

        if (! $known && ! $this->registry->knows($matcher)) {
            return null;
        }

        return CallTarget::resolved($arguments, $matcher, $known ? strtolower($key) : null, $display);
    }

    /**
     * `array( $receiver, 'method' )`, in both its object and its class-name form.
     *
     * @param list<string>  $methods
     * @param list<Operand> $arguments
     *
     * @return list<CallTarget>
     */
    private function fromPair(
        Operand $receiver,
        array $methods,
        array $arguments,
        FunctionContext $context,
        ClassTypeMap $types,
        ReceiverResolver $receivers,
    ): array {
        // `array( 'Acme_Renderer', 'render' )` — a class name, so static.
        $classNames = $this->values->strings($receiver);
        $static = $classNames !== [];
        $inferred = $receivers->classOf($receiver, $context, $types);
        $classes = $static ? $classNames : ($inferred === null ? [] : [$inferred]);

        $targets = [];

        foreach ($classes as $class) {
            $class = ltrim($class, '\\');

            if ($class === '') {
                continue;
            }

            if (in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
                $class = $context->className;

                if ($class === null) {
                    continue;
                }
            }

            foreach ($methods as $method) {
                $key = $class . '::' . $method;
                $matcher = $static ? Matcher::staticMethod($class, $method) : Matcher::method($class, $method);
                $target = $this->target($arguments, $matcher, $key, $key . '()');

                if ($target !== null) {
                    $targets[] = $target;
                }
            }
        }

        return $targets;
    }

    /**
     * Follow an operand back to a closure or arrow function declaration.
     *
     * Assignments are transparent, so `$a = fn () => …; $b = $a; $b();`
     * resolves. Anything that leaves the chain — a parameter, a property, a
     * call result — stops the walk.
     */
    public function closureBehind(Operand $operand, int $depth = 0): ?FunctionContext
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

    /**
     * An object used as a callable calls its `__invoke`.
     */
    private function invokableBehind(
        Operand $operand,
        FunctionContext $context,
        ClassTypeMap $types,
        ReceiverResolver $receivers,
    ): ?CallTarget {
        $class = $receivers->classOf($operand, $context, $types);

        if ($class === null || ! $this->functions->has($class . '::__invoke')) {
            return null;
        }

        return CallTarget::resolved(
            [],
            Matcher::method($class, '__invoke'),
            strtolower($class . '::__invoke'),
            $class . '::__invoke()',
        );
    }

    /**
     * Two branches assigning the same callback name is common, and analysing it
     * twice would double every finding it produces.
     *
     * @param list<CallTarget> $targets
     *
     * @return list<CallTarget>
     */
    private static function unique(array $targets): array
    {
        $seen = [];
        $unique = [];

        foreach ($targets as $target) {
            $identity = $target->identity();

            if (isset($seen[$identity])) {
                continue;
            }

            $seen[$identity] = true;
            $unique[] = $target;
        }

        return $unique;
    }
}
