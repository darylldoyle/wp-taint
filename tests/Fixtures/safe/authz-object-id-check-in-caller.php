<?php

/**
 * The object-scoped check in the handler, the operation in a helper.
 *
 * The helper's body contains no check, so its summary carries the sink; what
 * discharges it is the caller's frame, where current_user_can( 'delete_post',
 * $id ) dominates the call. Real handlers are written exactly this way, and
 * flagging the helper would report the code that got it right.
 */

add_action('wp_ajax_acme_remove_note', 'acme_remove_note');

function acme_remove_note()
{
    check_ajax_referer('acme-remove-note');

    $note_id = absint($_POST['note_id']);

    if (! current_user_can('delete_post', $note_id)) {
        wp_die(-1);
    }

    acme_forget_note($note_id);
}

function acme_forget_note($note_id)
{
    wp_delete_post($note_id, true);
}
