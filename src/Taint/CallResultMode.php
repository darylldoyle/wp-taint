<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Where a resolved callee's return value lands.
 *
 * A dispatcher decides this, not the callee. `array_map()` collects its callee's
 * returns into an array; `array_filter()` throws its predicate's boolean away
 * and hands back a subset of its input instead. Writing the predicate's result
 * onto the call would launder the input array's taint entirely.
 */
enum CallResultMode
{
    /** The call's own result operand. The ordinary case. */
    case Value;

    /** The result operand's element slot: `array_map()`. */
    case Container;

    /**
     * Nowhere. The callee is analysed for its sinks and its effects, but what
     * it returns is not what the call evaluates to.
     */
    case Discard;
}
