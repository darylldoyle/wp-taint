<?php

/**
 * A user-meta write on a request-chosen user, gated by being logged in.
 *
 * is_user_logged_in() proves a session exists — any subscriber's will do —
 * and $_POST['user_id'] picks whose row gets written. update_user_meta() on
 * an arbitrary user id is the canonical escalation shape: metadata drives
 * plugin-side permissions constantly, and core itself keeps capabilities in
 * user meta.
 */

add_action('wp_ajax_acme_dismiss_notice', 'acme_dismiss_notice');

function acme_dismiss_notice()
{
    check_ajax_referer('acme-dismiss');

    if (! is_user_logged_in()) {
        wp_die(-1);
    }

    update_user_meta(absint($_POST['user_id']), 'acme_notice_dismissed', 1); // wp-taint-expect wp.authz.object-id-from-request object_id
}
