<?php

/**
 * The same pair, naming the action at both ends.
 */

function acme_render_form_safe()
{
    wp_nonce_field('acme_delete_state');
    submit_button('Delete');
}

function acme_handle_form_safe()
{
    check_admin_referer('acme_delete_state');

    if (current_user_can('manage_options')) {
        delete_option('acme_state');
    }
}
