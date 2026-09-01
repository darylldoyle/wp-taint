<?php

/**
 * A capability the catalogue has never heard of.
 *
 * Plugins mint their own capabilities and typically grant them to
 * administrators; what acme_manage_reports covers is this plugin's own
 * capability model, which the engine cannot see. Treated as site-scoped —
 * the documented false negative beats guessing that a stranger's capability
 * is role-shaped.
 */

add_action('wp_ajax_acme_delete_report_row', 'acme_delete_report_row');

function acme_delete_report_row()
{
    check_ajax_referer('acme-delete-report-row');

    if (! current_user_can('acme_manage_reports')) {
        wp_die(-1);
    }

    wp_delete_post(absint($_POST['row_id']), true);
}
