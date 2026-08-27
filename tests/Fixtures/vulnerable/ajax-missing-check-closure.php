<?php

/**
 * The same gap with an inline closure callback.
 */

add_action('wp_ajax_acme_reset', static function () { // wp-taint-expect wp.authz.ajax-missing-check authz
    delete_option('acme_state');
    wp_send_json_success();
});
