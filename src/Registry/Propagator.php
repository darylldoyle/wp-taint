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
         * element under one joins the whole-array slot. Each element keeps
         * what it holds below itself, so every argument the entry reads must
         * be an array the result takes its elements from.
         */
        public readonly bool $keepsKeys = false,
        /**
         * The result is an array of its input's values under new keys:
         * `array_values()`. Each value keeps what it holds below itself,
         * under a computed key, so every argument the entry reads must be an
         * array the result takes its values from. `array_pad()` is not one:
         * its pad value is a single value of the result.
         */
        public readonly bool $keepsValues = false,
        /**
         * The result is one element of its input: `reset()`, `end()`,
         * `array_shift()`, or the first of the arguments
         * `apply_filters_ref_array()` takes. It keeps what that element holds
         * below itself.
         */
        public readonly bool $returnsElement = false,
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
        /**
         * `str_replace()`'s search and replacement. Text with no quote,
         * backtick or backslash in it cannot move an escaped value out of
         * its quotes, so the value keeps its residual; any other text, or
         * text the scan cannot read, turns it back into `sql`.
         *
         * @var list<int>
         */
        public readonly array $quoteArguments = [],
    ) {
    }
}
