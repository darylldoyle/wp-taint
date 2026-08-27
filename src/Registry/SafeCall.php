<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * A call that is explicitly not a sink, recorded so nobody adds it back.
 *
 * `wpdb::insert()`, `update()`, `delete()` and `replace()` escape their data
 * internally. Flagging them is a guaranteed false positive. Listing them here
 * is not documentation: {@see RegistryLoader} rejects any registry that
 * declares a sink matching a safe entry, so the mistake cannot be made
 * silently.
 */
final class SafeCall
{
    public function __construct(
        public readonly Matcher $matcher,
        public readonly string $note,
    ) {
    }
}
