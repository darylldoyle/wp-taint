<?php

/**
 * WP_REST_Server::EDITABLE covers POST, PUT and PATCH, so __return_true here is
 * the same bypass written a different way.
 */

register_rest_route('acme/v1', '/profile', [ // wp-taint-expect wp.authz.rest-public-write authz
    'methods' => WP_REST_Server::EDITABLE,
    'callback' => 'acme_update_profile',
    'permission_callback' => '__return_true',
]);
