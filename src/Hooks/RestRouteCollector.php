<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\ClassTypeMap;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ReceiverResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Reads every `register_rest_route()` into a {@see RestRouteTable}.
 *
 * On the control flow graph rather than the AST, so every callback, permission
 * callback and sanitize callback resolves through the same
 * {@see CallableResolver} the dataflow uses for any other callable: a function
 * name, `'Class::method'`, `[ $this, 'm' ]`, `[ Foo::class, 'm' ]`, a closure,
 * an arrow function or an invokable object, whichever it is written as.
 *
 * The options are read the way core's `register_rest_route()` reads them. A
 * definition with a `callback` is the only one; otherwise every integer-keyed
 * entry is a definition, and a shared `args` entry is merged into each.
 * Options that are not an array literal, directly or through assignment, are
 * recorded as unresolved rather than guessed at. A definition whose `args` is
 * built by a method call, as `WP_REST_Controller` subclasses do, still has its
 * callbacks read, with no schema.
 */
final class RestRouteCollector
{
    private const REGISTRAR = 'register_rest_route';

    /** How many plain assignments to follow back to an array literal. */
    private const MAX_DEPTH = 8;

    public function __construct(
        private readonly CallableResolver $callables,
        private readonly ReceiverResolver $receivers,
    ) {
    }

    /**
     * @param iterable<FunctionContext> $contexts
     */
    public function collect(iterable $contexts): RestRouteTable
    {
        $table = new RestRouteTable();

        foreach ($contexts as $context) {
            $types = new ClassTypeMap();

            foreach (BlockOrder::of($context->func->cfg) as $block) {
                foreach ($block->children as $op) {
                    $isCall = $op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall;

                    if ($isCall && self::isRegistrar($op)) {
                        $this->record($table, $op, $context, $types);
                    }
                }
            }
        }

        return $table;
    }

    private function record(
        RestRouteTable $table,
        Op\Expr\FuncCall|Op\Expr\NsFuncCall $op,
        FunctionContext $context,
        ClassTypeMap $types,
    ): void {
        $argument = $op->args[2] ?? null;
        $options = self::arrayBehind($argument instanceof Operand ? $argument : null);

        if ($options === null) {
            $table->recordUnresolved(
                $context->file->relativePath,
                $op->getLine(),
                'register_rest_route() options are not an array literal',
            );

            return;
        }

        $entries = self::entries($options);

        if ($entries === null) {
            $table->recordUnresolved(
                $context->file->relativePath,
                $op->getLine(),
                'register_rest_route() options have computed keys',
            );

            return;
        }

        $shared = isset($entries['args']) ? $this->arguments($entries['args'], $context, $types) : [];
        $definitions = isset($entries['callback']) ? [$options] : [];

        if ($definitions === []) {
            foreach ($entries as $key => $value) {
                $definition = is_int($key) ? self::arrayBehind($value) : null;

                if ($definition !== null) {
                    $definitions[] = $definition;
                }
            }
        }

        foreach ($definitions as $definition) {
            $fields = self::entries($definition);

            if ($fields === null || ! isset($fields['callback'])) {
                continue;
            }

            $own = isset($fields['args']) ? $this->arguments($fields['args'], $context, $types) : [];

            // array_merge( $common_args, $arg_group['args'] ): a definition's own
            // entry for a parameter replaces the shared one.
            $arguments = $shared === null || $own === null ? null : [...$shared, ...$own];

            $table->add(new RestRoute(
                $this->callables->resolve($fields['callback'], [], $context, $types, $this->receivers),
                isset($fields['permission_callback'])
                    ? $this->callables->resolve($fields['permission_callback'], [], $context, $types, $this->receivers)
                    : null,
                $arguments,
                $context->file->relativePath,
                $op->getLine(),
            ));
        }
    }

    /**
     * An `args` schema, or null when it is not readable.
     *
     * @return array<string, RestArgument>|null
     */
    private function arguments(Operand $operand, FunctionContext $context, ClassTypeMap $types): ?array
    {
        $schema = self::arrayBehind($operand);
        $entries = $schema === null ? null : self::entries($schema);

        if ($entries === null) {
            return null;
        }

        $arguments = [];

        foreach ($entries as $name => $value) {
            if (! is_string($name)) {
                continue;
            }

            $entry = self::arrayBehind($value);
            $fields = $entry === null ? null : self::entries($entry);

            if ($fields === null) {
                $arguments[$name] = RestArgument::unknown();

                continue;
            }

            $sanitizers = null;
            $disabled = false;

            if (array_key_exists('sanitize_callback', $fields)) {
                $callback = $fields['sanitize_callback'];

                // `empty( $param_args['sanitize_callback'] )` is core's test.
                if (self::isEmptyValue($callback)) {
                    $disabled = true;
                } else {
                    $sanitizers = $this->callables->resolve($callback, [], $context, $types, $this->receivers);
                }
            }

            $arguments[$name] = new RestArgument(
                $sanitizers,
                $disabled,
                isset($fields['type']) ? self::lowerString($fields['type']) : null,
                isset($fields['format']) ? self::lowerString($fields['format']) : null,
                isset($fields['enum']),
            );
        }

        return $arguments;
    }

    /**
     * The array literal an operand holds, through plain assignments.
     */
    private static function arrayBehind(?Operand $operand, int $depth = 0): ?Op\Expr\Array_
    {
        if ($operand === null || $depth > self::MAX_DEPTH) {
            return null;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Array_) {
            return $definition;
        }

        if ($definition instanceof Op\Expr\Assign) {
            return self::arrayBehind($definition->expr, $depth + 1);
        }

        return null;
    }

    /**
     * An array literal's entries by key, or null when a key is computed.
     *
     * A later entry with the same key wins, as in PHP.
     *
     * @return array<array-key, Operand>|null
     */
    private static function entries(Op\Expr\Array_ $array): ?array
    {
        $entries = [];
        $next = 0;

        foreach ($array->values as $index => $value) {
            if (! $value instanceof Operand) {
                continue;
            }

            $key = $array->keys[$index] ?? null;

            // An implicit key is php-cfg's NullOperand, not a missing entry.
            if ($key === null || $key instanceof Operand\NullOperand) {
                $entries[$next++] = $value;

                continue;
            }

            if (! $key instanceof Operand) {
                return null;
            }

            $literal = OperandHelper::literalValue($key);

            if (! is_string($literal) && ! is_int($literal)) {
                return null;
            }

            $entries[$literal] = $value;

            if (is_int($literal) && $literal >= $next) {
                $next = $literal + 1;
            }
        }

        return $entries;
    }

    /**
     * `null`, `false`, `''` or `0`, written as a literal or as a constant.
     */
    private static function isEmptyValue(Operand $operand): bool
    {
        if ($operand instanceof Operand\Literal) {
            return ! $operand->value;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\ConstFetch) {
            $name = OperandHelper::literalString($definition->name);

            return $name !== null && in_array(strtolower(ltrim($name, '\\')), ['null', 'false'], true);
        }

        return false;
    }

    private static function lowerString(Operand $operand): ?string
    {
        $value = OperandHelper::literalString($operand);

        return $value === null ? null : strtolower($value);
    }

    private static function isRegistrar(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): bool
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        foreach ($names as $name) {
            if ($name !== null && strtolower(ltrim($name, '\\')) === self::REGISTRAR) {
                return true;
            }
        }

        return false;
    }
}
