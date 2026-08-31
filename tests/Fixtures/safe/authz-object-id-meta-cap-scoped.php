<?php

/**
 * The correct shape: the meta capability with the id in hand.
 *
 * current_user_can( 'delete_post', $id ) resolves through map_meta_cap()
 * against that specific post — author, status, post type — which is exactly
 * the question an object operation needs answered. The dominating check
 * discharges the object-id finding.
 */

add_action('wp_ajax_acme_delete_draft', 'acme_delete_draft');

function acme_delete_draft()
{
    check_ajax_referer('acme-delete-draft');

    $id = absint($_POST['id']);

    if (! current_user_can('delete_post', $id)) {
        wp_die(-1);
    }

    wp_delete_post($id, true);

    wp_send_json_success();
}
