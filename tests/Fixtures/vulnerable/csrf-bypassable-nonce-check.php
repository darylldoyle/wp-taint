<?php

/**
 * Send no nonce at all and isset() is false, so the conjunction is false and
 * wp_verify_nonce() never runs. The request decides whether it is checked.
 */

function acme_save_settings()
{
    if (
        isset($_REQUEST['nonce']) // wp-taint-expect wp.csrf.bypassable-nonce-check authz
        && ! wp_verify_nonce($_REQUEST['nonce'], 'acme_settings')
    ) {
        wp_die('Bad nonce.');
    }

    update_option('acme_enabled', '1');
}
