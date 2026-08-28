<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Taint\TaintKind;

/**
 * Somewhere tainted data becomes a vulnerability.
 */
final class Sink
{
    /**
     * Fire only when no part of the value is fixed by the code.
     *
     * For an option name, `'acme_' . $_POST['x']` and `$_POST['x'] . '_optin'`
     * are a different bug from `$_POST['x']`: the first two let an attacker
     * create junk in a namespace the plugin already owns, the third lets them
     * set `default_role`. Without this the rule reports the common idiom and
     * buries the real one. See {@see LiteralAnchor}.
     */
    public const UNANCHORED = 'unanchored';

    /**
     * Fire only when the call can actually instantiate an object.
     *
     * `unserialize( $data, [ 'allowed_classes' => false ] )` returns arrays and
     * scalars and nothing else, so no POP chain can run. It is the documented
     * fix for this whole class — it is what Better Search Replace shipped for
     * CVE-2023-6933 — and reporting code that already applies it would be
     * telling people to do the thing they have done.
     */
    public const UNSERIALIZE_ALLOWS_OBJECTS = 'unserialize_allows_objects';

    public const STRATEGIES = [self::UNANCHORED, self::UNSERIALIZE_ALLOWS_OBJECTS];

    public function __construct(
        public readonly Matcher $matcher,
        public readonly ArgumentSelector $arguments,
        public readonly TaintKind $kind,
        public readonly Severity $severity,
        public readonly string $ruleId,
        public readonly ?string $note = null,
        /**
         * The write side of second-order taint: `update_option()` and friends.
         * Off unless `--stored-taint-writes` is passed, because on most
         * codebases these dominate the output.
         */
        public readonly bool $storedWrite = false,
        /** A named condition on whether this sink fires at all. */
        public readonly ?string $appliesBy = null,
    ) {
    }
}
