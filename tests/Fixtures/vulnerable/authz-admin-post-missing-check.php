<?php

/**
 * admin-post.php dispatches ?action=acme_delete to admin_post_acme_delete.
 * The nonce proves the request was deliberate; nothing proves the caller may
 * delete anything, so any logged-in subscriber can.
 */

add_action('admin_post_acme_delete', 'acme_delete_row'); // wp-taint-expect wp.authz.admin-post-missing-check authz

function acme_delete_row()
{
    check_admin_referer('acme_delete');

    global $wpdb;
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}acme WHERE id = %d", absint($_POST['id'])));
}
