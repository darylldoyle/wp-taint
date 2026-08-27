<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

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
    ) {
    }

    public function apply(TaintSet $incoming): TaintSet
    {
        if ($this->clearsEverything) {
            return TaintSet::empty();
        }

        return $incoming->without($this->clears);
    }

    public function describeClears(): string
    {
        return $this->clearsEverything ? '*' : $this->clears->describe();
    }
}
