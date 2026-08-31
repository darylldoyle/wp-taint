<?php

/**
 * The role check lives in the handler and the operation one helper down.
 *
 * The helper's own body contains no check at all, so its summary records the
 * sink; the handler's frame is where the question is re-asked, and the answer
 * there is a role capability, which entitles the caller to nothing in
 * particular. The finding lands on the helper's line, where the fix goes.
 */

add_action('wp_ajax_acme_purge_log', 'acme_purge_log');

function acme_purge_log()
{
    check_ajax_referer('acme-purge-log');

    if (! current_user_can('edit_posts')) {
        wp_die(-1);
    }

    acme_do_purge(absint($_POST['log_id']));
}

function acme_do_purge($log_id)
{
    wp_delete_post($log_id, true); // wp-taint-expect wp.authz.object-id-from-request object_id
}
