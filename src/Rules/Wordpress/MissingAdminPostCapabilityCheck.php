<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;

/**
 * An admin-post handler with neither a capability check nor a nonce check.
 *
 * `admin-post.php?action=foo` dispatches to `admin_post_foo`, and the nopriv
 * variant to `admin_post_nopriv_foo`. Being under wp-admin implies nothing:
 * admin-post.php is reachable by any logged-in user, and by anyone at all on
 * the nopriv hook. The file is a router, not a gate.
 *
 * This is the third registrar of the shape the REST and AJAX rules already
 * cover, and the one that was missing. The WordPress plugin team's own
 * intentionally vulnerable plugin puts its row-deletion handler here with no
 * capability check, and we reported the file clean.
 */
final class MissingAdminPostCapabilityCheck extends HookHandlerAuthorization
{
    protected function ruleId(): string
    {
        return 'wp.authz.admin-post-missing-check';
    }

    /**
     * @return list<string>
     */
    protected function hookPrefixes(): array
    {
        return ['admin_post_'];
    }

    /**
     * A nonce is not enough here.
     *
     * The plugin this rule was written against calls check_admin_referer() in
     * its delete handler and has no capability check at all. That stops the
     * deletion being cross-site and leaves any subscriber able to delete rows,
     * which is the vulnerability the answer key records. Accepting the nonce
     * would report the file clean for the same reason we did before.
     *
     * @return list<string>
     */
    protected function acceptedChecks(Registry $registry): array
    {
        return $registry->entitlementChecks();
    }

    protected function reachDescription(string $hook): string
    {
        return str_starts_with($hook, 'admin_post_nopriv_')
            ? 'Registered on admin-post.php\'s nopriv hook, so it is reachable by unauthenticated visitors.'
            : 'Registered on admin-post.php, which is reachable by any logged-in user, including a subscriber. '
                . 'Being under wp-admin is not an authorization check.';
    }

    protected function severityFor(string $hook): Severity
    {
        return str_starts_with($hook, 'admin_post_nopriv_') ? Severity::High : Severity::Medium;
    }
}
