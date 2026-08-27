<?php

/**
 * The same gap with an array callback, which the hook resolver must handle.
 */

class Acme_Ajax
{
    public function __construct()
    {
        add_action('wp_ajax_acme_purge', [$this, 'purge']); // wp-taint-expect wp.authz.ajax-missing-check authz
    }

    public function purge()
    {
        delete_option('acme_cache');
        wp_send_json_success();
    }
}
