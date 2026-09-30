<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * The class of a method call's receiver, when it is statically obvious.
 *
 * Shared by the direct-call resolver and the callable resolver: `$obj->run()`
 * and `call_user_func( array( $obj, 'run' ) )` have to agree about what `$obj`
 * is, or the same flow would be found through one and missed through the other.
 */
final class ReceiverResolver
{
    /**
     * Receiver variable names that are conventionally the WordPress database
     * handle. `$wpdb` is a global; the others are the two names plugins almost
     * universally use when they stash it on an object.
     */
    private const WPDB_RECEIVER_NAMES = ['wpdb', 'db'];

    /** How far a `a()->b->c->d()` chain is followed before giving up. */
    private const MAX_CHAIN = 8;

    /**
     * {@see namesSetOtherwise()}, by function.
     *
     * @var array<string, array<string, true>|true>
     */
    private array $setOtherwise = [];

    public function __construct(private readonly ?DeclaredTypes $declared = null)
    {
    }

    public function classOf(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
        return $this->resolve($receiver, $context, $types, 0);
    }

    /**
     * The class whose property `$receiver->p` reads or writes.
     *
     * {@see classOf()}, and past it the class PHP's own methods and functions
     * are declared to return: `$r->getClosureCalledClass()->name` is a
     * `ReflectionClass`'s name. Without it the read fell to the one slot every
     * unresolved `->name` shares, and Twig's compiler read Elementor's
     * request-filled post type labels out of it into `eval()`.
     *
     * Only for properties. A method call on such a value stays a dynamic
     * call, which follows its arguments into its result, where a resolved
     * call to a method the catalogue does not list returns nothing.
     *
     * A class something in the scan extends is not answered: the object could
     * be the subclass, whose properties are kept under its own name.
     */
    public function propertyOwnerOf(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
        return $this->classOf($receiver, $context, $types) ?? $this->internalClassOf($receiver, $context, $types, 0);
    }

    private function internalClassOf(Operand $value, FunctionContext $context, ClassTypeMap $types, int $depth): ?string
    {
        if ($depth > self::MAX_CHAIN || $this->declared === null) {
            return null;
        }

        $definition = OperandHelper::definingOp($value);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->classOf($definition->expr, $context, $types)
                ?? $this->internalClassOf($definition->expr, $context, $types, $depth + 1);
        }

        if ($definition instanceof Op\Phi) {
            /** @var SplObjectStorage<Op\Phi, true> $seen */
            $seen = new SplObjectStorage();
            $seen->attach($definition);
            $agreed = $this->agreedClassOf($definition, $context, $types, $depth + 1, $seen);

            return is_string($agreed) ? $agreed : null;
        }

        // A cast of an object hands back that object. The scan takes any
        // other value to be an array or a scalar, which the cast makes into
        // a new stdClass object.
        if ($definition instanceof Op\Expr\Cast\Object_) {
            return $this->classOf($definition->expr, $context, $types)
                ?? $this->internalClassOf($definition->expr, $context, $types, $depth + 1)
                ?? 'stdClass';
        }

        $class = null;

        if ($definition instanceof Op\Expr\MethodCall || $definition instanceof Op\Expr\StaticCall) {
            $method = OperandHelper::literalString($definition->name);
            $owner = $definition instanceof Op\Expr\StaticCall
                ? OperandHelper::literalString($definition->class)
                : $this->classOf($definition->var, $context, $types)
                    ?? $this->internalClassOf($definition->var, $context, $types, $depth + 1);

            $class = $method === null || $owner === null ? null : InternalTypes::methodReturnClass($owner, $method);
        } elseif ($definition instanceof Op\Expr\FuncCall) {
            // Not a namespaced call: the namespace's own function of that name
            // would be the one called, whatever PHP's returns.
            $function = OperandHelper::literalString($definition->name);
            $class = $function === null ? null : InternalTypes::functionReturnClass($function);
        }

        return $class === null || $this->declared->isExtended($class) ? null : $class;
    }

    /**
     * The one class every way into a join agrees on.
     *
     * `if ( $x && ( $class = $r->getClosureCalledClass() ) ) { $class->name }`
     * reads `$class` through the join php-cfg puts after `&&`, and the join
     * also takes in `$class` from before the condition. Every source has to
     * name the same class, or carry no object at all: a literal, or a local
     * the function never set (see {@see neverSetOtherwise()}). A source
     * naming nothing the resolver can see makes the join unknown.
     *
     * @param SplObjectStorage<Op\Phi, true> $seen joins already being followed, round a loop
     *
     * @return string|false|null the class; false when no source carries an object; null when unknown
     */
    private function agreedClassOf(
        Op\Phi $join,
        FunctionContext $context,
        ClassTypeMap $types,
        int $depth,
        SplObjectStorage $seen,
    ): string|false|null {
        if ($depth > self::MAX_CHAIN) {
            return null;
        }

        $agreed = false;

        foreach ($join->vars as $source) {
            if (! $source instanceof Operand) {
                return null;
            }

            $class = $this->sourceClassOf($source, $context, $types, $depth, $seen);

            if ($class === false) {
                continue;
            }

            if ($class === null || ($agreed !== false && strcasecmp($agreed, $class) !== 0)) {
                return null;
            }

            $agreed = $class;
        }

        return $agreed;
    }

    /**
     * @param SplObjectStorage<Op\Phi, true> $seen
     *
     * @return string|false|null see {@see agreedClassOf()}
     */
    private function sourceClassOf(
        Operand $source,
        FunctionContext $context,
        ClassTypeMap $types,
        int $depth,
        SplObjectStorage $seen,
    ): string|false|null {
        if (self::carriesNoObject($source)) {
            return false;
        }

        $definition = OperandHelper::definingOp($source);

        if ($definition instanceof Op\Expr\Assign && self::carriesNoObject($definition->expr)) {
            return false;
        }

        // No write at all: php-cfg's empty entry join, which the simplifier
        // removes and leaves the variable with no writer.
        if ($definition === null && $source->ops === []) {
            return $this->unsetUnlessSetOtherwise($source, $context);
        }

        if (! $definition instanceof Op\Phi) {
            return $this->classOf($source, $context, $types)
                ?? $this->internalClassOf($source, $context, $types, $depth + 1);
        }

        // Round a loop, the value on the way back in is one the other
        // sources already account for.
        if ($seen->contains($definition)) {
            return false;
        }

        $seen->attach($definition);

        if ($definition->vars === []) {
            return $this->unsetUnlessSetOtherwise($source, $context);
        }

        return $this->agreedClassOf($definition, $context, $types, $depth + 1, $seen);
    }

    /**
     * A literal, `null`, `true`, `false` or an array: nothing with a
     * property to read.
     */
    private static function carriesNoObject(Operand $value): bool
    {
        if ($value instanceof Operand\Literal) {
            return true;
        }

        $definition = OperandHelper::definingOp($value);

        if ($definition instanceof Op\Expr\Array_) {
            return true;
        }

        if (! $definition instanceof Op\Expr\ConstFetch) {
            return false;
        }

        $name = strtolower(ltrim(OperandHelper::literalString($definition->name) ?? '', '\\'));

        return in_array($name, ['null', 'true', 'false'], true);
    }

    /**
     * False, carrying no object, for a local nothing else can set; null,
     * unknown, otherwise.
     */
    private function unsetUnlessSetOtherwise(Operand $variable, FunctionContext $context): ?false
    {
        $name = OperandHelper::variableName($variable);

        return $name !== null && $this->neverSetOtherwise($name, $context) ? false : null;
    }

    /**
     * Whether a local variable php-cfg has no write for is unset.
     *
     * php-cfg gives a variable it sees no write for an empty join at the
     * function's entry. That is an unset local, but also a global, a static,
     * a closure's capture, a variable an included file or `extract()` sets,
     * and one a call fills through a by-reference parameter, which php-cfg
     * cannot see. So the variable counts as unset only in a function or
     * method with none of those: not declared global or static, never
     * passed to a call, never bound by reference or captured, and no
     * `include`, `eval`, `extract()`, `parse_str()` or variable variable in
     * the body. File scope and closures never qualify.
     */
    private function neverSetOtherwise(string $name, FunctionContext $context): bool
    {
        if ($context->isMain() || $context->isClosure()) {
            return false;
        }

        $this->setOtherwise[$context->key] ??= self::namesSetOtherwise($context);
        $set = $this->setOtherwise[$context->key];

        return $set !== true && ! isset($set[$name]);
    }

    /**
     * @return array<string, true>|true true when anything in the body can set any variable
     */
    private static function namesSetOtherwise(FunctionContext $context): array|true
    {
        $names = [];

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ($block->children as $op) {
                if (
                    $op instanceof Op\Expr\Include_
                    || $op instanceof Op\Expr\Eval_
                    || $op instanceof Op\Expr\VarVar
                ) {
                    return true;
                }

                $callee = $op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall
                    ? strtolower(ltrim(OperandHelper::literalString($op->name) ?? '', '\\'))
                    : null;

                if ($callee !== null && in_array($callee, ['extract', 'parse_str', 'mb_parse_str'], true)) {
                    return true;
                }

                $bound = match (true) {
                    $op instanceof Op\Terminal\GlobalVar, $op instanceof Op\Terminal\StaticVar => [$op->var],
                    $op instanceof Op\Expr\AssignRef => [$op->var, $op->expr],
                    $op instanceof Op\Expr\Closure => $op->useVars,
                    $op instanceof Op\Expr\FuncCall,
                    $op instanceof Op\Expr\NsFuncCall,
                    $op instanceof Op\Expr\MethodCall,
                    $op instanceof Op\Expr\StaticCall,
                    $op instanceof Op\Expr\New_ => $op->args,
                    default => [],
                };

                foreach ($bound as $operand) {
                    $bound = $operand instanceof Operand
                        ? OperandHelper::variableName($operand) ?? OperandHelper::literalString($operand)
                        : null;

                    if ($bound !== null) {
                        $names[$bound] = true;
                    }
                }
            }
        }

        return $names;
    }

    private function resolve(Operand $receiver, FunctionContext $context, ClassTypeMap $types, int $depth): ?string
    {
        if ($depth > self::MAX_CHAIN) {
            return null;
        }

        $name = OperandHelper::variableName($receiver);

        if ($name === 'this') {
            return $context->className;
        }

        // The convention is a fallback, not an override. `$wpdb` is a global
        // with no declaration to read, so the name is all there is — but
        // `function f( Acme_DB $db )` says what it is, and reading `$db` as the
        // database handle there resolved `$db->get_table_name()` to
        // `wpdb::get_table_name()`, a method nothing defines. The call then
        // failed to resolve, its origin was "unaccounted for", and the table
        // name it returns was reported as an unprepared query.
        $tracked = $types->classOf($receiver);

        if ($tracked !== null) {
            return $tracked;
        }

        if ($name !== null && in_array(strtolower($name), self::WPDB_RECEIVER_NAMES, true)) {
            return 'wpdb';
        }

        // `$this->wpdb->query()` and `$this->db->query()`: the receiver is a
        // property fetch, and these two property names are the near-universal
        // convention for stashing the database handle.
        $definition = OperandHelper::definingOp($receiver);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->resolve($definition->expr, $context, $types, $depth + 1);
        }

        // `$GLOBALS['wpdb']` is the global `$wpdb` by another spelling, and
        // uninstall scripts use it as often as `global $wpdb`.
        if (
            $definition instanceof Op\Expr\ArrayDimFetch
            && OperandHelper::variableName($definition->var) === 'GLOBALS'
            && $definition->dim instanceof Operand
        ) {
            $global = strtolower(OperandHelper::literalString($definition->dim) ?? '');

            return in_array($global, self::WPDB_RECEIVER_NAMES, true) ? 'wpdb' : null;
        }

        // `code_snippets()` returning `Plugin`, and `Plugin::make()` returning
        // `self`. Declared, never inferred — see DeclaredTypes.
        $returned = $this->returnedClass($definition, $context, $types, $depth);

        if ($returned !== null) {
            return $returned;
        }

        if ($definition instanceof Op\Expr\PropertyFetch) {
            $property = OperandHelper::literalString($definition->name);

            if ($property === null) {
                return null;
            }

            // Same order for the same reason: a declared `private Acme_DB $db`
            // outranks the convention, and `$this->db` with nothing declared
            // still falls back to it.
            $owner = $this->resolve($definition->var, $context, $types, $depth + 1);
            $declared = $types->classOfProperty($owner, $property)
                ?? $this->declared?->propertyClassOf($owner, $property);

            if ($declared !== null) {
                return $declared;
            }

            return in_array(strtolower($property), self::WPDB_RECEIVER_NAMES, true) ? 'wpdb' : null;
        }

        return null;
    }

    /**
     * The class a call was declared to return.
     *
     * The method form needs its own receiver resolved first, which is what
     * makes `aioseo()->core->db` work and what the depth limit is guarding.
     */
    private function returnedClass(
        ?Op $definition,
        FunctionContext $context,
        ClassTypeMap $types,
        int $depth,
    ): ?string {
        if ($this->declared === null) {
            return null;
        }

        if ($definition instanceof Op\Expr\NsFuncCall) {
            // A namespaced call falls back to the global function when the
            // namespaced one does not exist, so both names have to be tried,
            // in that order — the same order CallResolver uses. Reading only
            // `name` asks about `code_snippets()` when the code declares
            // `Code_Snippets\code_snippets(): Plugin`, and the chain stops
            // one step in.
            $namespaced = OperandHelper::literalString($definition->nsName);
            $global = OperandHelper::literalString($definition->name);

            return ($namespaced === null ? null : $this->declared->returnClassOf($namespaced))
                ?? ($global === null ? null : $this->declared->returnClassOf($global));
        }

        if ($definition instanceof Op\Expr\FuncCall) {
            $name = OperandHelper::literalString($definition->name);

            return $name === null ? null : $this->declared->returnClassOf($name);
        }

        if (! $definition instanceof Op\Expr\MethodCall && ! $definition instanceof Op\Expr\StaticCall) {
            return null;
        }

        $method = OperandHelper::literalString($definition->name);

        if ($method === null) {
            return null;
        }

        $owner = $definition instanceof Op\Expr\StaticCall
            ? OperandHelper::literalString($definition->class)
            : $this->resolve($definition->var, $context, $types, $depth + 1);

        return $owner === null ? null : $this->declared->returnClassOf($owner . '::' . $method);
    }
}
