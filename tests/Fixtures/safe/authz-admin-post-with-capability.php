<?php

/**
 * The same handler with the capability check the nonce cannot substitute for.
 */

add_action('admin_post_acme_delete', 'acme_delete_row_safe');

function acme_delete_row_safe()
{
    check_admin_referer('acme_delete');

    if (! current_user_can('manage_options')) {
        wp_die('Permission denied.');
    }

    global $wpdb;
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}acme WHERE id = %d", absint($_POST['id'])));
}
