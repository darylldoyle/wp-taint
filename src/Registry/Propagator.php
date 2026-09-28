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
        /**
         * The result keeps an escaped SQL value's residual, `sql_unquoted` or
         * `sql_self_quoted`, because the function cannot undo the escaping:
         * `strtolower()`, `array_filter()`. Every other propagator turns it
         * back into `sql`, since `stripslashes()` or `rawurldecode()` can.
         */
        public readonly bool $keepsResiduals = false,
        /**
         * With an argument at this position the residual goes back to `sql`
         * after all: `trim( $v, '\\' )` can strip an escaping backslash.
         */
        public readonly ?int $maskArgument = null,
        /**
         * A `printf` format at this position. A literal one is read, and its
         * arguments folded where it puts them; see
         * {@see \Enshrined\WpTaint\Taint\PrintfFormat}.
         */
        public readonly ?int $formatArgument = null,
        /** The values follow the format as one array, as `vsprintf()` takes them. */
        public readonly bool $formatArray = false,
        /**
         * `implode()`'s glue. A literal glue that leaves the quotes as it found
         * them keeps the elements' residuals; any other glue turns them back
         * into `sql`.
         */
        public readonly ?int $glueArgument = null,
        /**
         * `str_replace()` read by its literal search and replacement: doubling
         * or removing backticks escapes for an identifier, and escaping the
         * backslash and then both quotes escapes for a quoted literal.
         */
        public readonly bool $readsEscapes = false,
    ) {
    }
}
