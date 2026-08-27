<?php

/**
 * check_ajax_referer() verifies the nonce and dies on failure.
 */

add_action('wp_ajax_nopriv_acme_subscribe', 'acme_ajax_subscribe');

function acme_ajax_subscribe()
{
    check_ajax_referer('acme_subscribe');

    add_option('acme_subscriber', sanitize_email(wp_unslash($_POST['email'])));

    wp_die('ok');
}
