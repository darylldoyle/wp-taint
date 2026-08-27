<?php

/**
 * WP_REST_Server::READABLE is GET, so the same reasoning applies.
 */

register_rest_route('acme/v1', '/feed', [
    'methods' => WP_REST_Server::READABLE,
    'callback' => 'acme_feed',
    'permission_callback' => '__return_true',
]);
