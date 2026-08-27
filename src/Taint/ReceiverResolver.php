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
                : $types->classOfProperty($this->classOf($definition->var, $context, $types), $property);
        }

        return null;
    }
}
