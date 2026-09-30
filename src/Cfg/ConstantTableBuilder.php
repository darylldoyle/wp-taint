<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\FunctionContext;
use Enshrined\WpTaint\Taint\OperandHelper;
use Enshrined\WpTaint\Taint\ThisReceiver;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Collects every `define()` call and `const` declaration in the scan.
 *
 * Runs once, before analysis, for the same reason the hook graph does:
 * constants are static facts about the code and nothing about them depends on
 * taint.
 *
 * Two passes over the same contexts, because a constant is routinely defined in
 * terms of another one:
 *
 * ```php
 * define( 'ACME_FILE', __FILE__ );
 * define( 'ACME_DIR', dirname( ACME_FILE ) . '/' );
 * ```
 *
 * The first pass resolves what it can from literals; the second re-runs with
 * those in hand. Two rather than a fixed point because chains longer than that
 * are rare and the cost is a whole extra walk.
 *
 * Each pass builds a *fresh* table, reading the previous one. Accumulating into
 * a single table defeated the whole design: a constant the first pass could not
 * resolve was marked unresolvable, and nothing in the second pass could clear
 * that — so `define( 'WC_ABSPATH', dirname( WC_PLUGIN_FILE ) . '/' )`, the exact
 * shape the second pass exists for, stayed unresolved forever.
 */
final class ConstantTableBuilder
{
    private const PASSES = 2;

    public function __construct(private readonly ValueResolver $values)
    {
    }

    /**
     * @param iterable<FunctionContext> $contexts
     */
    public function build(iterable $contexts): ConstantTable
    {
        return $this->buildBoth($contexts)['constants'];
    }

    /**
     * Constants and constant returns together, because each helps the other.
     *
     * `define( 'ACME_DIR', … )` may be built from a function's return, and a
     * function's return is routinely built from a constant. Two passes over
     * both, with each pass reading the last one's answers.
     *
     * @param iterable<FunctionContext> $contexts
     *
     * @return array{constants: ConstantTable, returns: ConstantReturnTable}
     */
    public function buildBoth(iterable $contexts): array
    {
        $table = new ConstantTable();
        $returns = new ConstantReturnTable();

        for ($pass = 0; $pass < self::PASSES; $pass++) {
            $resolver = $this->values->withConstants($table, $returns);
            $next = new ConstantTable();
            $nextReturns = new ConstantReturnTable();

            foreach ($contexts as $context) {
                // A class's body is a block of its own, reached after the op
                // that declares the class. Its constants are the class's.
                $classBodies = [];

                foreach (BlockOrder::of($context->func->cfg) as $block) {
                    $class = $classBodies[spl_object_id($block)] ?? null;

                    foreach ($block->children as $op) {
                        if ($op instanceof Op\Stmt\ClassLike) {
                            $name = OperandHelper::literalString($op->name);

                            if ($name !== null) {
                                $classBodies[spl_object_id($op->stmts)] = $name;
                            }
                        }

                        $this->collect($next, $resolver, $op, $class, $context);
                    }
                }

                $this->collectReturn($nextReturns, $resolver, $context);
            }

            $table = $next;
            $returns = $nextReturns;
        }

        return ['constants' => $table, 'returns' => $returns];
    }

    /**
     * A body whose every `return` yields the same constant string.
     *
     * Every one, and the same one. A function returning a path on one branch
     * and something else on another is not a constant, and treating it as one
     * would resolve an include to a file the code never loads.
     */
    private function collectReturn(
        ConstantReturnTable $returns,
        ValueResolver $resolver,
        FunctionContext $context,
    ): void {
        if ($context->isMain()) {
            return;
        }

        $choices = self::choicesOf($resolver, $context);

        if ($choices !== null && count($choices) > 1) {
            $returns->recordChoices($context->key, $choices);
        }

        $values = [];
        $templates = [];

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Terminal\Return_) {
                    continue;
                }

                // A bare `return;` means the function can hand back null, so it
                // does not always yield the string.
                if ($op->expr === null) {
                    return;
                }

                $resolved = $resolver->strings($op->expr);

                if (count($resolved) === 1) {
                    $values[] = $resolved[0];

                    continue;
                }

                // Not a constant. It may still be a *template* — literal
                // fragments around the function's own parameters — which a call
                // with literal arguments folds exactly. See
                // {@see ConstantReturnTable::$templates}.
                $template = $this->templateOf($op->expr, $resolver, $context);

                if ($template === null) {
                    return;
                }

                $templates[] = $template;
            }
        }

        if ($templates !== []) {
            // Constants and templates from different branches of one function
            // do not merge, and neither do two different templates: any
            // disagreement between returns means the answer depends on control
            // flow this pass does not model.
            $unique = array_unique($templates, SORT_REGULAR);
            $first = reset($unique);

            if ($values === [] && count($unique) === 1 && $first !== false) {
                $returns->recordTemplate($context->key, $first);
            }

            return;
        }

        $unique = array_unique($values);

        if (count($unique) === 1) {
            $returns->record($context->key, reset($unique));
        }
    }

    /**
     * Every string a function can return, when each of its returns folds to
     * a known few: `$operator = 'AND'; ... $operator = 'OR'; return
     * $operator;`. Null when any return may hand back something else, a bare
     * `return;` included.
     *
     * @return list<string>|null
     */
    private static function choicesOf(ValueResolver $resolver, FunctionContext $context): ?array
    {
        $choices = [];

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (! $op instanceof Op\Terminal\Return_) {
                    continue;
                }

                $strings = $op->expr === null ? [] : $resolver->keyStrings($op->expr);

                if ($strings === []) {
                    return null;
                }

                $choices = [...$choices, ...$strings];
            }
        }

        $choices = array_values(array_unique($choices));
        sort($choices);

        return $choices === [] ? null : $choices;
    }

    /**
     * A return expression as literal fragments around the function's own
     * parameters, or null when any part is neither.
     *
     * Strict on purpose. A part that is a *transformed* parameter —
     * `basename( $view )`, `$view . $suffix` — is not the parameter, and
     * substituting the caller's argument into it would fold to a path the
     * code never builds.
     *
     * @return list<string|int>|null
     */
    private function templateOf(
        Operand $expr,
        ValueResolver $resolver,
        FunctionContext $context,
    ): ?array {
        $parts = self::flattenConcat($expr, 0);

        if ($parts === null) {
            return null;
        }

        $parameters = [];

        foreach (array_values($context->func->params) as $index => $param) {
            if ($param instanceof Op\Expr\Param) {
                $parameters[spl_object_id($param->result)] = $index;
            }
        }

        $segments = [];

        foreach ($parts as $part) {
            if (! $part instanceof Operand) {
                return null;
            }

            $index = $parameters[spl_object_id($part)] ?? null;

            if ($index !== null) {
                $segments[] = $index;

                continue;
            }

            $resolved = $resolver->strings($part);

            if (count($resolved) !== 1) {
                return null;
            }

            $segments[] = $resolved[0];
        }

        // A template with no parameter in it is a constant that failed to
        // resolve for some other reason; recording it would hide that.
        return array_filter($segments, 'is_int') === [] ? null : $segments;
    }

    /**
     * Every atomic operand of a concatenation, however it nests.
     *
     * `__DIR__ . "/views/$view"` is not one concat: the interpolated string is
     * its own op whose result feeds the outer one, so the parameter sits two
     * levels down. Flattening walks through Concat, ConcatList and plain
     * assignments; anything else is an atom for the caller to classify.
     *
     * @return list<Operand>|null null when nesting exceeds the budget
     */
    private static function flattenConcat(Operand $operand, int $depth): ?array
    {
        if ($depth > 8) {
            return null;
        }

        $definition = OperandHelper::definingOp($operand);

        $parts = match (true) {
            $definition instanceof Op\Expr\ConcatList => $definition->list,
            $definition instanceof Op\Expr\BinaryOp\Concat => [$definition->left, $definition->right],
            $definition instanceof Op\Expr\Assign => [$definition->expr],
            default => null,
        };

        if ($parts === null) {
            return [$operand];
        }

        $flat = [];

        foreach ($parts as $part) {
            if (! $part instanceof Operand) {
                return null;
            }

            $inner = self::flattenConcat($part, $depth + 1);

            if ($inner === null) {
                return null;
            }

            $flat = [...$flat, ...$inner];
        }

        return $flat;
    }

    private function collect(
        ConstantTable $table,
        ValueResolver $resolver,
        mixed $op,
        ?string $class = null,
        ?FunctionContext $context = null,
    ): void {
        // A private property declared as a literal array, and every write to a
        // property of any name, so a read can tell whether the declaration is
        // still its value. See ConstantTable::fixedPropertyDefault().
        if ($op instanceof Op\Stmt\Property) {
            $name = OperandHelper::literalString($op->name);

            if (
                $class !== null
                && $name !== null
                && $op->isPrivate()
                && ! $op->static
                && $op->defaultVar !== null
                && OperandHelper::definingOp($op->defaultVar) instanceof Op\Expr\Array_
            ) {
                $table->declareFixedProperty($name, $op->defaultVar);
            }

            return;
        }

        if ($op instanceof Op\Expr\PropertyFetch) {
            $name = OperandHelper::literalString($op->name);

            // An assignment to the property is a writer of the fetch's
            // result, not a usage of it.
            $assigned = OperandHelper::isWrittenElsewhere($op->result, $op);

            if ($assigned || self::mayChange($op->result, 0)) {
                $table->markPropertyWritten($name);
            }

            if ($assigned || self::mayRebind($op->result)) {
                $site = $context === null ? null : self::allocationAssigned($op, $context);

                if ($site !== null && $name !== null && $context?->className !== null) {
                    $method = ThisReceiver::inInstanceMethod($context) && ! $context->isClosure()
                        ? $context->func->name
                        : null;
                    $table->recordPropertyAllocation($context->className, $name, $site, $method);
                } else {
                    $onThis = OperandHelper::variableName($op->var) === 'this';

                    // A computed name on another object, `$wpdb->$table = ...`,
                    // is taken to be a value of that object's own. Read as
                    // any property of any object, one such line anywhere
                    // left every property of the scan unknown.
                    if ($onThis || $name !== null) {
                        $table->markPropertyNotAllocated($onThis ? $context?->className : null, $name);
                    }
                }
            }

            return;
        }

        // `const NAME = 'value';` — php-cfg gives it its own terminal, with the
        // name already resolved. Inside a class body it is the class's, and
        // its name is the bare one: recorded as a global, `class A { const
        // VERSION = '1'; }` defined `VERSION` for the whole scan.
        if ($op instanceof Op\Terminal\Const_) {
            $name = OperandHelper::literalString($op->name);

            if ($name === null) {
                return;
            }

            $value = self::single($resolver->strings($op->value));

            if ($class !== null) {
                $table->defineClassConstant($class, $name, $value);
                $table->defineClassConstantList($class, $name, self::literalStrings($op->value));
            } else {
                $table->define($name, $value);
            }

            return;
        }

        if (! self::isDefine($op)) {
            return;
        }

        /** @var Op\Expr\FuncCall|Op\Expr\NsFuncCall|Op\Expr\MethodCall|Op\Expr\StaticCall $op */
        $arguments = [];

        foreach ($op->args as $argument) {
            if ($argument instanceof Operand) {
                $arguments[] = $argument;
            }
        }

        if (count($arguments) < 2) {
            return;
        }

        $name = OperandHelper::literalString($arguments[0]);

        if ($name === null) {
            return;
        }

        $table->define($name, self::single($resolver->strings($arguments[1])));
    }

    /**
     * The allocation site of `$this->name = new Acme_Query( ... )`, when that
     * assignment is the one thing done to the fetch. Null for anything else.
     */
    private static function allocationAssigned(Op\Expr\PropertyFetch $fetch, FunctionContext $context): ?string
    {
        if (OperandHelper::variableName($fetch->var) !== 'this' || self::mayRebind($fetch->result)) {
            return null;
        }

        $writers = [];

        foreach ($fetch->result->ops as $writer) {
            if ($writer !== $fetch) {
                $writers[] = $writer;
            }
        }

        $assign = $writers[0] ?? null;

        if (count($writers) !== 1 || ! $assign instanceof Op\Expr\Assign || $assign->var !== $fetch->result) {
            return null;
        }

        $new = OperandHelper::definingOp($assign->expr);

        if (! $new instanceof Op\Expr\New_) {
            return null;
        }

        $class = OperandHelper::literalString($new->class);

        if ($class === null || in_array(strtolower($class), ['self', 'static', 'parent'], true)) {
            return null;
        }

        return ConstantTable::allocationSite($class, $context->file->relativePath, $new->getLine());
    }

    /**
     * Whether a property fetch's result is used in a way that could make the
     * property hold a different object: assigned, bound by reference, or the
     * base of an element write. A method call on the object it holds, a read
     * of one of that object's properties, or handing it to a call, leaves it
     * holding the same object.
     */
    private static function mayRebind(Operand $operand): bool
    {
        foreach ($operand->usages as $usage) {
            $keeps = match (true) {
                // An object handed to a call is the same object when it comes
                // back. Only a parameter taken by reference could put another
                // there, and WordPress code does not pass objects that way.
                $usage instanceof Op\Expr\MethodCall,
                $usage instanceof Op\Expr\StaticCall,
                $usage instanceof Op\Expr\FuncCall,
                $usage instanceof Op\Expr\NsFuncCall,
                $usage instanceof Op\Expr\New_ => true,
                // Unset leaves no object, so none the property could hold.
                $usage instanceof Op\Terminal\Unset_ => true,
                $usage instanceof Op\Expr\PropertyFetch => $usage->var === $operand,
                $usage instanceof Op\Expr\Assign => $usage->expr === $operand && $usage->var !== $operand,
                $usage instanceof Op\Expr\Isset_,
                $usage instanceof Op\Expr\Empty_,
                $usage instanceof Op\Expr\InstanceOf_ => true,
                $usage instanceof Op\Expr\ArrayDimFetch => $usage->var === $operand
                    && ! OperandHelper::isWrittenElsewhere($usage->result, $usage)
                    && ! self::mayChange($usage->result, 1),
                default => false,
            };

            if (! $keeps) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a property fetch's result is used in any way that could change
     * the property: written, bound by reference, unset, handed to a call, or
     * the base of an element write. A read, a copy, a loop over it and a
     * read of one of its elements leave it as it is.
     */
    private static function mayChange(Operand $operand, int $depth): bool
    {
        if ($depth > 8) {
            return true;
        }

        foreach ($operand->usages as $usage) {
            $reads = match (true) {
                $usage instanceof Op\Iterator\Reset,
                $usage instanceof Op\Iterator\Valid,
                $usage instanceof Op\Iterator\Key,
                $usage instanceof Op\Expr\Isset_,
                $usage instanceof Op\Expr\Empty_ => true,
                $usage instanceof Op\Iterator\Value => ! $usage->byRef,
                $usage instanceof Op\Expr\Assign => $usage->expr === $operand && $usage->var !== $operand,
                $usage instanceof Op\Expr\ArrayDimFetch => $usage->var === $operand
                    && ! OperandHelper::isWrittenElsewhere($usage->result, $usage)
                    && ! self::mayChange($usage->result, $depth + 1),
                default => false,
            };

            if (! $reads) {
                return true;
            }
        }

        return false;
    }

    /**
     * The strings in an array literal, or null when it is not one or holds
     * anything but literal strings.
     *
     * @return list<string>|null
     */
    private static function literalStrings(Operand $operand): ?array
    {
        $definition = OperandHelper::definingOp($operand);

        if (! $definition instanceof Op\Expr\Array_ || $definition->values === []) {
            return null;
        }

        $strings = [];

        foreach ($definition->values as $value) {
            if (! $value instanceof Operand\Literal || ! is_string($value->value)) {
                return null;
            }

            $strings[] = $value->value;
        }

        return $strings;
    }

    /**
     * A constant with several possible values is recorded as unresolvable
     * rather than as any one of them.
     *
     * The value resolver returns sets everywhere else, and a set would be
     * defensible here too — but a constant is a single value at runtime, and
     * carrying an "either" through path resolution would produce includes of
     * files the build never actually loads.
     *
     * @param list<string> $values
     */
    private static function single(array $values): ?string
    {
        return count($values) === 1 ? $values[0] : null;
    }

    /**
     * A call that defines a constant, however it is spelled.
     *
     * Plugins routinely wrap `define()` in a method of their own —
     * `$this->define( 'WC_ABSPATH', … )` guards against redefinition — and
     * WooCommerce declares every one of its constants that way. Matching only
     * the global function left 446 of its include sites unresolvable.
     *
     * Any callable named `define` counts. A method of that name which does
     * something else would record a constant that does not exist, and the cost
     * of that is a path that resolves to no file in the scan — which is exactly
     * what happens today anyway.
     */
    private static function isDefine(mixed $op): bool
    {
        $names = match (true) {
            $op instanceof Op\Expr\NsFuncCall => [
                OperandHelper::literalString($op->nsName),
                OperandHelper::literalString($op->name),
            ],
            $op instanceof Op\Expr\FuncCall,
            $op instanceof Op\Expr\MethodCall,
            $op instanceof Op\Expr\StaticCall => [OperandHelper::literalString($op->name)],
            default => [],
        };

        foreach ($names as $name) {
            if ($name !== null && strtolower(ltrim($name, '\\')) === 'define') {
                return true;
            }
        }

        return false;
    }
}
