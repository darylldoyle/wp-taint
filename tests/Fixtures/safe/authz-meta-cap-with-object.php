<?php

/**
 * Meta capabilities used the way map_meta_cap() expects.
 *
 * Each call names the row it is asking about, including through user_can()
 * and author_can(), whose capability sits one argument later. A computed
 * capability is left alone too: it could be anything, including an
 * object-scoped one paired with the id below it.
 */

function acme_can_touch($post_id, $user, $cap)
{
    if (! current_user_can('edit_post', $post_id)) {
        return false;
    }

    if (! user_can($user, 'delete_post', $post_id)) {
        return false;
    }

    if (! author_can($post_id, 'edit_post', $post_id)) {
        return false;
    }

    return current_user_can($cap);
}
