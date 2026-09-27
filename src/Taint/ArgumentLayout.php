<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\CompatibilityVisitor;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Which value each of a callee's parameters receives.
 *
 * php-cfg lists a call's arguments in the order they were written, and the
 * analysis hands the argument at position `i` to parameter `i`. That is wrong
 * in four ways, and each lost a flow:
 *
 * - `f( ...$args )` hands `$args`'s elements to every parameter from there on,
 *   but the analysis gave the whole array to the first and nothing to the rest.
 * - `f( label: $x, field: $y )` goes by name. Read by position, `$x` reached
 *   whichever parameter came first.
 * - `function f( $a, ...$rest )` collects every argument after `$a` into
 *   `$rest`. The third argument went to a parameter that does not exist.
 * - `call_user_func_array( $cb, $args )` is `$cb( ...$args )`.
 *
 * A value that reaches a parameter as one of several, or as an element of an
 * array, is not that parameter's value, so the target stops being positional:
 * see {@see CallTarget::$positional}.
 */
final class ArgumentLayout
{
    private const UNPACKED = '...';

    public function __construct(private readonly UserFunctionTable $functions)
    {
    }

    /**
     * Lay out the arguments of a call written with `...` or names, or of a
     * callee that takes a variadic parameter.
     *
     * @param array<int, array{0: Operand, 1: string|null}> $written the call's arguments and how each was
     *                                                               written; see
     *                                                               {@see CompatibilityVisitor::UNPACKED_OR_NAMED_ARGUMENTS}
     */
    public function lay(CallTarget $target, array $written): CallTarget
    {
        $parameters = $this->parametersOf($target);

        if ($parameters === null) {
            return $written === [] ? $target : $target->notPositional();
        }

        $forms = self::formsOf($target->arguments, $written);

        if (! in_array(true, array_map(static fn (?string $form): bool => $form !== null, $forms), true)
            && self::variadicAt($parameters) === null
        ) {
            return $target;
        }

        $laid = new ParameterSlots($parameters);

        foreach ($target->arguments as $index => $argument) {
            $form = $forms[$index] ?? null;

            match (true) {
                $form === null => $laid->next($argument),
                $form === self::UNPACKED => $laid->everyRemaining($argument),
                default => $laid->named($form, $argument),
            };
        }

        return $laid->onto($target);
    }

    /**
     * `call_user_func_array( $cb, $args )`, `do_action_ref_array( $h, $args )`.
     *
     * An array written in the call, `array( $a, $b )` or `[ 'label' => $x ]`,
     * hands its values to the parameters its keys name, as PHP does. Any
     * other array could hold anything by then, so its element taint goes to
     * every parameter.
     */
    public function spread(CallTarget $target): CallTarget
    {
        $parameters = $this->parametersOf($target);
        $array = $target->arguments[0] ?? null;

        if ($parameters === null || $array === null) {
            return $target->notPositional();
        }

        $laid = new ParameterSlots($parameters);
        $literal = OperandHelper::definingOp($array);

        if (! $literal instanceof Op\Expr\Array_ || ! self::keysAreLiteral($literal)) {
            $laid->everyRemaining($array);

            return $laid->onto($target->notPositional());
        }

        foreach ($literal->values as $index => $value) {
            if (! $value instanceof Operand) {
                continue;
            }

            $keyOperand = $literal->keys[$index] ?? null;
            $key = $keyOperand instanceof Operand ? OperandHelper::literalKey($keyOperand) : null;

            is_string($key) ? $laid->named($key, $value) : $laid->next($value);
        }

        return $laid->onto($target);
    }

    /**
     * A dispatcher whose catalogue entry says where each parameter's value
     * comes from: `array_walk( $items, $cb, $extra )` is `$cb( $item, $key,
     * $extra )`.
     *
     * @param list<list<int>> $sources per parameter, the dispatcher's arguments it receives
     */
    public static function fromSources(CallTarget $target, CallTarget $dispatch, array $sources): CallTarget
    {
        $arguments = [];
        $more = [];

        foreach ($sources as $position => $indexes) {
            $operands = [];

            foreach ($indexes as $index) {
                $operand = $dispatch->argument($index);

                if ($operand !== null) {
                    $operands[] = $operand;
                }
            }

            $arguments[$position] = array_shift($operands) ?? new Operand\Literal(null);

            if ($operands !== []) {
                $more[$position] = $operands;
            }
        }

        return $target->withParameterArguments(array_values($arguments), $more, false);
    }

    /**
     * The call's arguments, each paired with how it was written.
     *
     * @return array<int, array{0: Operand, 1: string|null}>
     */
    public static function written(Op $op): array
    {
        $forms = $op->getAttribute(CompatibilityVisitor::UNPACKED_OR_NAMED_ARGUMENTS);
        $arguments = $op instanceof Op\Expr\FuncCall
            || $op instanceof Op\Expr\NsFuncCall
            || $op instanceof Op\Expr\MethodCall
            || $op instanceof Op\Expr\StaticCall
            || $op instanceof Op\Expr\New_
                ? $op->args
                : [];

        $written = [];

        foreach (array_values($arguments) as $index => $argument) {
            if ($argument instanceof Operand) {
                $form = is_array($forms) ? ($forms[$index] ?? null) : null;
                $written[] = [$argument, is_string($form) ? $form : null];
            }
        }

        return $written;
    }

    /**
     * @return list<array{name: string|null, byRef: bool, variadic: bool}>|null
     */
    private function parametersOf(CallTarget $target): ?array
    {
        $meta = $target->userFunctionKey === null ? null : $this->functions->get($target->userFunctionKey);

        return $meta?->parameters;
    }

    /**
     * How each of the target's arguments was written, found by identity: a
     * dispatcher hands its callee a slice of its own arguments.
     *
     * @param list<Operand>                                 $arguments
     * @param array<int, array{0: Operand, 1: string|null}> $written
     *
     * @return list<string|null>
     */
    private static function formsOf(array $arguments, array $written): array
    {
        $forms = [];

        foreach ($arguments as $argument) {
            $form = null;

            foreach ($written as $index => [$operand, $how]) {
                if ($operand === $argument) {
                    $form = $how;
                    unset($written[$index]);

                    break;
                }
            }

            $forms[] = $form;
        }

        return $forms;
    }

    /**
     * @param list<array{name: string|null, byRef: bool, variadic: bool}> $parameters
     */
    public static function variadicAt(array $parameters): ?int
    {
        foreach ($parameters as $index => $parameter) {
            if ($parameter['variadic']) {
                return $index;
            }
        }

        return null;
    }

    private static function keysAreLiteral(Op\Expr\Array_ $array): bool
    {
        foreach ($array->keys as $key) {
            if ($key instanceof Operand && OperandHelper::literalKey($key) === null && ! self::isNull($key)) {
                return false;
            }
        }

        return true;
    }

    private static function isNull(Operand $operand): bool
    {
        return $operand instanceof Operand\NullOperand
            || ($operand instanceof Operand\Literal && $operand->value === null);
    }
}
