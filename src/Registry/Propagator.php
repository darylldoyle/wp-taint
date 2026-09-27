<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * Something that passes taint through unchanged.
 *
 * The `note` is load-bearing. `wp_unslash()` lives here, and the note is what
 * stops the next person moving it into `[[sanitizers]]` — the single most
 * common misunderstanding in WordPress code review.
 */
final class Propagator
{
    public function __construct(
        public readonly Matcher $matcher,
        public readonly ArgumentSelector $arguments,
        public readonly ?string $note = null,
        /**
         * The result is an array under its input's keys: `array_filter()`,
         * `array_merge()`, `apply_filters()` on an array. An element under a
         * string key stays under that key, so `$args['id']` does not take the
         * taint of `$args['value']`. An integer key can be renumbered, so an
         * element under one joins the whole-array slot.
         */
        public readonly bool $keepsKeys = false,
    ) {
    }
}
