<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;

/**
 * An AJAX handler with neither a capability check nor a nonce check.
 *
 * `wp_ajax_*` is reachable by any logged-in user, including a subscriber;
 * `wp_ajax_nopriv_*` is reachable by anyone at all.
 *
 * The walk that decides whether anything checked is in
 * {@see HookHandlerAuthorization}, shared with the admin_post_ rule.
 */
final class MissingAjaxCapabilityCheck extends HookHandlerAuthorization
{
    protected function ruleId(): string
    {
        return 'wp.authz.ajax-missing-check';
    }

    /**
     * A nonce counts here.
     *
     * Not because it should — a nonce proves intent, not entitlement — but
     * because AJAX handlers overwhelmingly guard with check_ajax_referer()
     * alone, and demanding a capability as well would bury the real findings
     * under every plugin in the corpus. The admin_post_ rule holds the higher
     * bar; this one is the pragmatic floor.
     *
     * @return list<string>
     */
    protected function acceptedChecks(Registry $registry): array
    {
        return $registry->authorizationChecks();
    }

    /**
     * @return list<string>
     */
    protected function hookPrefixes(): array
    {
        return ['wp_ajax_'];
    }

    protected function reachDescription(string $hook): string
    {
        return str_starts_with($hook, 'wp_ajax_nopriv_')
            ? 'Registered on a nopriv hook, so it is reachable by unauthenticated visitors.'
            : 'Registered on an authenticated AJAX hook, so it is reachable by any logged-in user, including a '
                . 'subscriber.';
    }

    protected function severityFor(string $hook): Severity
    {
        return str_starts_with($hook, 'wp_ajax_nopriv_') ? Severity::High : Severity::Medium;
    }
}
