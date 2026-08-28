<?php

/**
 * The same guard, stopped properly.
 */

function acme_update_settings_safe()
{
    if (! current_user_can('manage_options')) {
        wp_safe_redirect(admin_url('options-general.php'));
        exit;
    }

    update_option('acme_enabled', '1');
}
