<?php

/**
 * An authenticated AJAX handler with no capability check and no nonce check.
 * Any logged-in subscriber can call it.
 */

add_action('wp_ajax_acme_save_settings', 'acme_ajax_save_settings'); // wp-taint-expect wp.authz.ajax-missing-check authz

function acme_ajax_save_settings()
{
    update_option('acme_settings', $_POST['settings']);

    wp_send_json_success();
}
