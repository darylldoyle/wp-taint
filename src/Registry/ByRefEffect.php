<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * A call that writes back through one of its arguments.
 *
 * ```php
 * preg_match( '/(\d+)/', $_GET['q'], $matches );
 * echo $matches[1];                                // reported now; silent before
 *
 * parse_str( $_SERVER['QUERY_STRING'], $out );
 * echo $out['redirect'];
 * ```
 *
 * `parse_str()` is the one that matters most: a real WordPress idiom, taking
 * attacker-controlled input by definition, and a silent false negative until
 * this existed.
 *
 * ## Only ever adds
 *
 * The engine's lattice only grows, so a by-reference write unions into whatever
 * the caller's variable already held rather than replacing it. That is the
 * conservative direction, and it is what keeps the fixed point monotone: SSA
 * does not give a by-reference write its own operand, so this and whatever else
 * writes that variable share one slot.
 *
 * The cost is that a call which genuinely *overwrites* its argument with
 * something clean — `similar_text( $a, $b, $percent )` — cannot be modelled as
 * clearing it. Listing such a function here would achieve nothing, so none are
 * listed.
 */
final class ByRefEffect
{
    /**
     * @param list<int> $from arguments whose taint flows into the written one
     */
    public function __construct(
        public readonly Matcher $matcher,
        public readonly int $writes,
        public readonly array $from,
        /**
         * True when the value lands *inside* the written argument rather than
         * being it. `preg_match()` fills an array with the captures, so the
         * taint belongs in the element slot; reading `$matches[1]` finds it,
         * and `echo $matches` — which prints "Array" — does not.
         */
        public readonly bool $asContainer = false,
        public readonly ?string $note = null,
    ) {
    }
}
