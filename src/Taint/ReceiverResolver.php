<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;

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

    public function __construct(private readonly ?DeclaredTypes $declared = null)
    {
    }

    public function classOf(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
        return $this->resolve($receiver, $context, $types, 0);
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
