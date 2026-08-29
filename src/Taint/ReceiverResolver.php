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

    public function classOf(Operand $receiver, FunctionContext $context, ClassTypeMap $types): ?string
    {
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

        if ($definition instanceof Op\Expr\PropertyFetch) {
            $property = OperandHelper::literalString($definition->name);

            if ($property === null) {
                return null;
            }

            // Same order for the same reason: a declared `private Acme_DB $db`
            // outranks the convention, and `$this->db` with nothing declared
            // still falls back to it.
            $declared = $types->classOfProperty($this->classOf($definition->var, $context, $types), $property);

            if ($declared !== null) {
                return $declared;
            }

            return in_array(strtolower($property), self::WPDB_RECEIVER_NAMES, true) ? 'wpdb' : null;
        }

        return null;
    }
}
