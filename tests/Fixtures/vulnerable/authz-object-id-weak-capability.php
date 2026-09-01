<?php

/**
 * The classic WordPress IDOR: a nonce, a role capability, and an object
 * operation on whichever row the request names.
 *
 * Every check here passes review at a glance. The nonce proves the request
 * came from a form this site rendered; edit_posts proves the caller has a
 * role. Neither says anything about whose post $_POST['id'] names, and
 * absint() does not help — 7 is a well-formed attack when post 7 belongs to
 * someone else.
 */

add_action('wp_ajax_acme_delete_report', 'acme_delete_report');

function acme_delete_report()
{
    check_ajax_referer('acme-delete-report');

    if (! current_user_can('edit_posts')) {
        wp_die(-1);
    }

    wp_delete_post(absint($_POST['id']), true); // wp-taint-expect wp.authz.object-id-from-request object_id

    wp_send_json_success();
}
