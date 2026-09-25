<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

/**
 * Something that removes specific taint kinds from a value.
 */
final class Sanitizer
{
    /**
     * Strategies {@see $clearsBy} accepts. Named here so a typo in a catalogue
     * is a load error rather than a silently inert entry.
     */
    public const ALLOWLIST_PATTERN = 'allowlist_pattern';

    public const STRATEGIES = [self::ALLOWLIST_PATTERN];

    public function __construct(
        public readonly Matcher $matcher,
        public readonly ArgumentSelector $arguments,
        public readonly TaintSet $clears,
        public readonly bool $clearsEverything = false,
        /**
         * The argument index that must be an effectively literal string for
         * this entry to sanitise at all.
         *
         * `$wpdb->prepare()` only protects when its first argument is a literal
         * format string. When that argument is itself built from a variable,
         * prepare() provides no protection and the call is a sink rather than a
         * sanitizer.
         */
        public readonly ?int $requiresLiteralArgument = null,
        public readonly ?string $note = null,
        /**
         * True when the clearing is context-dependent and the engine is
         * approximating. Findings downstream of it are marked imprecise.
         */
        public readonly bool $imprecise = false,
        /**
         * Rule to report when `requiresLiteralArgument` is violated.
         */
        public readonly ?string $literalViolationRuleId = null,
        /**
         * A named strategy that works out what this call clears from its
         * arguments, rather than the fixed `clears` set.
         *
         * `preg_replace( '/[^a-z0-9]/', '', $v )` clears almost everything and
         * `preg_replace( '/x/', $y, $v )` clears nothing, and no static entry
         * can say which. The strategy lives in code because it has to parse the
         * pattern; the binding lives here so the engine has no function names in
         * it.
         */
        public readonly ?string $clearsBy = null,
        public readonly int $patternArgument = 0,
        public readonly int $replacementArgument = 1,
        /**
         * This entry defends a quoted SQL context and only a quoted one.
         *
         * `esc_sql()`, `wpdb::_real_escape()` and `like_escape()` escape quotes
         * and backslashes. Bare, with no quotes around the value, there is
         * nothing to escape and `1 OR 1=1` passes through. So they clear `sql`
         * and leave {@see TaintKind::SqlUnquoted} behind, which the sink reports
         * only when the value lands outside quotes.
         *
         * The rest of the sanitize_* family that clears `sql` is genuinely safe
         * bare, because it restricts the character set: sanitize_key() and
         * sanitize_title() cannot emit a space or an operator, so there is no
         * payload to write.
         */
        public readonly bool $quotedOnly = false,
    ) {
    }

    public function apply(TaintSet $incoming): TaintSet
    {
        if ($this->clearsEverything) {
            return TaintSet::empty();
        }

        return $incoming->without($this->clears);
    }

    /**
     * What a value carries after this sanitizer runs on it.
     *
     * The escaping markers are the caller's business; everything else about
     * running a sanitizer is here, so a call in the code and a
     * `sanitize_callback` WordPress runs on a REST parameter are credited
     * exactly alike.
     *
     * @param TaintSet|null $strategyCleared what a `clears_by` strategy worked out the call clears, which needs
     *                                       the call's arguments; null for a sanitizer without one
     */
    public function transform(TaintSet $incoming, ?TaintSet $strategyCleared = null): TaintSet
    {
        $cleared = $strategyCleared === null ? $this->apply($incoming) : $incoming->without($strategyCleared);

        // Applying any sanitizer settles two questions whatever else it did or
        // did not clear: where the value came from, and whether anyone cleaned
        // it before storing it. Propagators settle neither, which is what keeps
        // `trim()` and `wp_unslash()` from passing for sanitisers.
        $cleared = $cleared->without(TaintSet::of(TaintKind::Unknown, TaintKind::Storage));

        // No sanitizer settles whose row an id names. absint() clears `*`
        // because it ends every payload, and an object id is not a payload:
        // `7` is a complete attack when post 7 is someone else's. Authorization
        // is CapabilityGuard's question, asked at the sink.
        if ($incoming->has(TaintKind::ObjectId)) {
            $cleared = $cleared->union(TaintSet::of(TaintKind::ObjectId));
        }

        // A quote-escaper does not remove the danger, it moves it: the value is
        // safe between quotes and no safer than before without them. Trading
        // `sql` for `sql_unquoted` is what lets the sink tell those apart, and
        // what keeps a table name from a helper — which never carried `sql` —
        // out of it entirely.
        if ($this->quotedOnly && $incoming->has(TaintKind::Sql)) {
            $cleared = $cleared->union(TaintSet::of(TaintKind::SqlUnquoted));
        }

        return $cleared;
    }

    public function describeClears(): string
    {
        return $this->clearsEverything ? '*' : $this->clears->describe();
    }
}
