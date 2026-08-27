<?php

/**
 * __return_true on a read-only route is a deliberate choice for public data,
 * not a bypass. Only write methods are reported.
 */

register_rest_route('acme/v1', '/public-items', [
    'methods' => 'GET',
    'callback' => 'acme_list_public_items',
    'permission_callback' => '__return_true',
]);
