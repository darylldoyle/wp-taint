<?php

/**
 * A write route with a real capability check.
 */

register_rest_route('acme/v1', '/settings', [
    'methods' => 'POST',
    'callback' => 'acme_update_settings',
    'permission_callback' => static function () {
        return current_user_can('manage_options');
    },
]);
