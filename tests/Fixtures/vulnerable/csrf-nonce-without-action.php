<?php

/**
 * Both ends default to the -1 action, so the token is shared with every other
 * bare nonce on the site and no longer ties the request to this operation.
 */

function acme_render_form()
{
    wp_nonce_field(); // wp-taint-expect wp.csrf.nonce-without-action authz
    submit_button('Delete');
}

function acme_handle_form()
{
    check_admin_referer(); // wp-taint-expect wp.csrf.nonce-without-action authz

    if (current_user_can('manage_options')) {
        delete_option('acme_state');
    }
}
