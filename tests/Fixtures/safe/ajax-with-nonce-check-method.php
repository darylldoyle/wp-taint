<?php

/**
 * The array-callback form with a nonce check.
 */

class Acme_Ajax
{
    public function __construct()
    {
        add_action('wp_ajax_acme_purge', [$this, 'purge']);
    }

    public function purge()
    {
        if (! wp_verify_nonce($_POST['_wpnonce'] ?? '', 'acme_purge')) {
            wp_send_json_error(null, 403);
        }

        delete_option('acme_cache');
        wp_send_json_success();
    }
}
