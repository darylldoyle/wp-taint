<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Taint\TaintSet;

/**
 * Something that introduces untrusted data.
 */
final class Source
{
    /**
     * Strategies {@see $appliesBy} accepts. Named here so a typo in a catalogue
     * is a load error rather than a silently inert entry.
     */
    public const ADD_QUERY_ARG_BASE = 'add_query_arg_base';

    public const STRATEGIES = [self::ADD_QUERY_ARG_BASE];

    public function __construct(
        public readonly Matcher $matcher,
        public readonly TaintSet $kinds,
        public readonly bool $stored = false,
        public readonly ?string $note = null,
        /**
         * Only treat this as a source when the literal at `arg` contains this
         * substring. Used for `file_get_contents('php://input')`, which is a
         * source for exactly one argument value and a filesystem sink for
         * every other.
         */
        public readonly ?string $argumentLiteralContains = null,
        public readonly int $argumentIndex = 0,
        /**
         * Superglobal keys that are attacker-controlled. Null means every key.
         * `$_SERVER` is the reason this exists: treating all of it as tainted
         * makes the false positive rate unmanageable.
         *
         * @var list<string>|null
         */
        public readonly ?array $keys = null,
        /**
         * Key prefixes that are attacker-controlled, e.g. `HTTP_` on `$_SERVER`.
         *
         * @var list<string>
         */
        public readonly array $keyPrefixes = [],
        /**
         * A named strategy deciding whether this entry is a source *at this
         * call site*.
         *
         * `add_query_arg()` reads `$_SERVER['REQUEST_URI']` only when no base
         * URI was passed to it. Whether one was depends on the shape of the
         * first argument, which no static field can say — and getting it wrong
         * either way is a false SSRF finding or a missed reflected one.
         */
        public readonly ?string $appliesBy = null,
    ) {
    }

    /**
     * Whether a superglobal access with this key is tainted.
     *
     * An unknown key — a dynamic index the engine cannot resolve — is treated
     * as tainted when the source has a key allowlist, because an attacker who
     * controls the index controls the value.
     */
    public function matchesKey(?string $key): bool
    {
        if ($this->keys === null && $this->keyPrefixes === []) {
            return true;
        }

        if ($key === null) {
            return true;
        }

        if ($this->keys !== null && in_array($key, $this->keys, true)) {
            return true;
        }

        foreach ($this->keyPrefixes as $prefix) {
            if (str_starts_with($key, $prefix)) {
                return true;
            }
        }

        return false;
    }
}
