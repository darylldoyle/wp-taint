<?php

/**
 * The plugin boilerplate registers hooks through its own loader rather than
 * calling add_action() where a scanner can see it. Eight of the fifty corpus
 * plugins do this, and a registration nobody sees is an authorization rule that
 * silently never ran.
 */

class Acme_Admin
{
    public function delete_entry()
    {
        global $wpdb;

        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}acme WHERE id = %d", absint($_POST['id'])));
    }
}

class Acme_Plugin
{
    private $loader;

    private function define_admin_hooks()
    {
        $plugin_admin = new Acme_Admin();

        $this->loader->add_action( // wp-taint-expect wp.authz.ajax-missing-check authz
            'wp_ajax_acme_delete',
            $plugin_admin,
            'delete_entry',
        );
    }
}
