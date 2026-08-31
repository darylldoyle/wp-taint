<?php

/**
 * The meta capability is the right check — called wrong.
 *
 * current_user_can( 'edit_post' ) without an id resolves against no row at
 * all: map_meta_cap() has nothing to map, WordPress 6.1 raises
 * _doing_it_wrong for the shape, and what the call returns is fallback
 * behaviour rather than a statement about $_POST['post_id']. The operation
 * below it stays unscoped, so both findings stand — the broken check, and
 * the request-chosen id it fails to cover.
 */

add_action('wp_ajax_acme_archive_post', 'acme_archive_post');

function acme_archive_post()
{
    check_ajax_referer('acme-archive');

    if (! current_user_can('edit_post')) { // wp-taint-expect wp.authz.meta-cap-without-object authz
        wp_die(-1);
    }

    wp_trash_post(intval($_POST['post_id'])); // wp-taint-expect wp.authz.object-id-from-request object_id
}
