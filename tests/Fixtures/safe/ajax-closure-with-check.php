<?php

/**
 * The inline closure form with a capability check.
 */

add_action('wp_ajax_acme_reset', static function () {
    if (! current_user_can('manage_options')) {
        wp_send_json_error(null, 403);
    }

    delete_option('acme_state');
    wp_send_json_success();
});
