<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * What a dispatcher hands back.
 *
 * Not every dispatcher returns what the callee returned. `array_filter()` runs
 * a predicate and returns a subset of its *input*; treating the predicate's
 * boolean as the result would launder the array's taint away entirely.
 */
enum DispatchReturn: string
{
    /** The callee's return value: `call_user_func()`. */
    case Callee = 'callee';

    /** An array of the callee's return values: `array_map()`. */
    case CalleeArray = 'callee_array';

    /**
     * Nothing from the callee. The dispatcher's own catalogue entry decides
     * what comes back — `array_filter()` and `usort()` both fall here, and both
     * are already modelled as propagators of their input array.
     */
    case Own = 'own';
}
