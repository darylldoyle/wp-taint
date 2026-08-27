<?php

/**
 * A nopriv AJAX handler is reachable by anonymous users, so a missing nonce
 * check is worse here than on the authenticated variant.
 */

add_action('wp_ajax_nopriv_acme_subscribe', 'acme_ajax_subscribe'); // wp-taint-expect wp.authz.ajax-missing-check authz

function acme_ajax_subscribe()
{
    add_option('acme_subscriber_' . $_POST['email'], 1);

    wp_die('ok');
}
