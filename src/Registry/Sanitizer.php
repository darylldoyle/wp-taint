<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Taint\TaintSet;

/**
 * Something that removes specific taint kinds from a value.
 */
final class Sanitizer
{
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
