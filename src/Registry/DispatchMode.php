<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * How a dispatcher's own arguments map onto the callee's.
 */
enum DispatchMode: string
{
    /**
     * The rest of the argument list, positionally: `call_user_func( $cb, $a, $b )`
     * calls `$cb( $a, $b )`.
     */
    case Rest = 'rest';

    /**
     * One argument holds an array of the callee's arguments:
     * `call_user_func_array( $cb, $args )` calls `$cb( ...$args )`.
     *
     * The elements are not individually addressable — SSA gives the array one
     * operand — so every parameter is fed the array's element taint. That is an
     * over-approximation in the parameter index and a sound one in the taint.
     */
    case Spread = 'spread';

    /**
     * One argument holds an array whose elements are each passed alone:
     * `array_map( $cb, $items )` calls `$cb( $item )` per element.
     */
    case Elements = 'elements';
}
