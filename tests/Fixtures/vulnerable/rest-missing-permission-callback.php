<?php

/**
 * A REST route registered with no permission_callback at all. WordPress treats
 * this as public, and since 5.5 emits a _doing_it_wrong notice.
 */

add_action('rest_api_init', 'acme_register_routes');

function acme_register_routes()
{
    register_rest_route('acme/v1', '/settings', [ // wp-taint-expect wp.authz.rest-missing-permission-callback authz
        'methods' => 'POST',
        'callback' => 'acme_update_settings',
    ]);
}

function acme_update_settings($request)
{
    update_option('acme_settings', $request->get_param('settings'));
}
