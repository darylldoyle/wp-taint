<?php

/**
 * An AJAX handler with a capability check.
 */

add_action('wp_ajax_acme_save_settings', 'acme_ajax_save_settings');

function acme_ajax_save_settings()
{
    if (! current_user_can('manage_options')) {
        wp_send_json_error(null, 403);
    }

    update_option('acme_settings', sanitize_text_field(wp_unslash($_POST['settings'])));

    wp_send_json_success();
}
