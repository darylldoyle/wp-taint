<?php

/**
 * The same registration through the same loader, with the check in place.
 */

class Acme_Admin_Safe
{
    public function delete_entry()
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(null, 403);
        }

        global $wpdb;

        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}acme WHERE id = %d", absint($_POST['id'])));
    }
}

class Acme_Plugin_Safe
{
    private $loader;

    private function define_admin_hooks()
    {
        $plugin_admin = new Acme_Admin_Safe();
        $this->loader->add_action('wp_ajax_acme_delete_safe', $plugin_admin, 'delete_entry');
    }
}
