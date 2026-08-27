<?php

/**
 * permission_callback => '__return_true' on a write route is an authorization
 * bypass, not a permission check.
 */

register_rest_route('acme/v1', '/items/(?P<id>\d+)', [ // wp-taint-expect wp.authz.rest-public-write authz
    'methods' => 'DELETE',
    'callback' => 'acme_delete_item',
    'permission_callback' => '__return_true',
]);
