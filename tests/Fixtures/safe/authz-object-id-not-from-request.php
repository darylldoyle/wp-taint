<?php

/**
 * The id the plugin chose, not the request.
 *
 * The row being deleted comes out of an option this plugin wrote at install
 * time. Stored data carries its own kinds; a request-chosen object id is not
 * one of them, because the question this rule asks — may the caller touch the
 * row the *request* names — has no request in it here.
 */

add_action('wp_ajax_acme_reset_landing_page', 'acme_reset_landing_page');

function acme_reset_landing_page()
{
    check_ajax_referer('acme-reset-landing');

    if (! current_user_can('edit_posts')) {
        wp_die(-1);
    }

    wp_delete_post((int) get_option('acme_landing_page_id'), true);

    delete_option('acme_landing_page_id');
}
