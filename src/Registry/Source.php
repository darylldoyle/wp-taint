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
        /**
         * Second-level keys that are attacker-controlled, for a superglobal
         * whose first level is a name the code chooses.
         *
         * `$_FILES` is the reason this exists. Its first level is the form
         * field name and its second is a fixed set, of which PHP writes most:
         *
         *     $_FILES['import']['name']       the client's filename
         *     $_FILES['import']['type']       the client's content type
         *     $_FILES['import']['tmp_name']   PHP's own path under upload_tmp_dir
         *     $_FILES['import']['size']       an int, from PHP
         *     $_FILES['import']['error']      an int, from PHP
         *
         * Tainting all of it made `file_get_contents( $_FILES['f']['tmp_name'] )`
         * a path-traversal finding in ten plugins. That call is not a mistake;
         * it is the only way to read an upload, and the path in it was never the
         * client's to choose.
         *
         * @var list<string>|null
         */
        public readonly ?array $subKeys = null,
    ) {
    }

    /**
     * Whether a second-level access with this key is tainted.
     *
     * A dynamic key is tainted, the same way {@see matchesKey} treats one: an
     * attacker who chooses the index chooses the value.
     */
    public function matchesSubKey(?string $key): bool
    {
        return $this->subKeys === null || $key === null || in_array($key, $this->subKeys, true);
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
