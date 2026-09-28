<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * The functions only an administrator can reach.
 *
 * Administrators are trusted in WordPress. An option only they can write holds
 * what an administrator chose. A later read of it is not request data,
 * whatever the write looked like.
 *
 * ```php
 * function acme_settings_page() {               // add_options_page( …, 'manage_options', … )
 *     update_option( 'acme', array( 'target' => $_POST['url'] ) );
 * }
 *
 * $settings = get_option( 'acme' );
 * wp_redirect( $settings['target'] );           // the administrator's own choice
 * ```
 *
 * A function is here when every way the scan can see to reach it passes a
 * check that the caller holds a site-wide grant. The check can be the admin
 * page the function runs on, registered with such a grant. It can be a REST
 * route's permission callback that requires one. Or it can dominate the call
 * or include that leads here. {@see AdministratorReachBuilder} decides it, and
 * {@see CapabilityGuard::siteWide()} says what counts as the check.
 *
 * Only the functions on some path to an option write are decided. Any other
 * function answers no, so its writes keep what they carry.
 */
final class AdministratorReach
{
    /**
     * @param array<string, true> $only function keys only an administrator can reach
     */
    public function __construct(private readonly array $only = [])
    {
    }

    public function onlyAdministratorsReach(string $key): bool
    {
        return isset($this->only[strtolower($key)]);
    }
}
