<?php

/**
 * wp_safe_redirect() sends a header and returns. The guard fails, the redirect
 * is queued, and the option write below runs anyway.
 */

function acme_update_settings()
{
    if (! current_user_can('manage_options')) {
        wp_safe_redirect(admin_url('options-general.php')); // wp-taint-expect wp.authz.guard-without-exit authz
    }

    update_option('acme_enabled', '1');
}
