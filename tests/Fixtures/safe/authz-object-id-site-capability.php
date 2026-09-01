<?php

/**
 * A site-wide grant entitles cross-object action.
 *
 * manage_options is not scoped to any row and does not need to be: a caller
 * holding it administers the site, and an admin deleting whichever post an
 * admin-screen request names is every bulk-actions table in existence.
 * Reporting this would flag the standard shape of wp-admin.
 */

add_action('admin_post_acme_remove_entry', 'acme_remove_entry');

function acme_remove_entry()
{
    check_admin_referer('acme-remove-entry');

    if (! current_user_can('manage_options')) {
        wp_die(-1);
    }

    wp_delete_post((int) $_POST['entry_id'], true);
}
