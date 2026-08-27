<?php

/**
 * A named permission callback is equally acceptable.
 */

register_rest_route('acme/v1', '/items', [
    'methods' => 'DELETE',
    'callback' => 'acme_delete_items',
    'permission_callback' => 'acme_can_delete_items',
]);

function acme_can_delete_items()
{
    return current_user_can('delete_posts');
}
