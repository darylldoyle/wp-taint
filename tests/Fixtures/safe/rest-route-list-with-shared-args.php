<?php

/**
 * register_rest_route() also takes a *list* of route definitions, with an
 * optional shared `args` schema alongside them.
 *
 * Only the integer-keyed entries are routes. Treating the `args` block as one
 * reported it for having no permission_callback, which a schema block neither
 * has nor should have. Taken from Akismet.
 */

register_rest_route(
    'acme/v1',
    '/stats/(?P<interval>[\w+])',
    array(
        'args' => array(
            'interval' => array(
                'description' => 'The period to retrieve stats for.',
                'type' => 'string',
            ),
        ),
        array(
            'methods' => WP_REST_Server::READABLE,
            'permission_callback' => array('Acme_Rest', 'privileged_permission_callback'),
            'callback' => array('Acme_Rest', 'get_stats'),
        ),
        array(
            'methods' => WP_REST_Server::EDITABLE,
            'permission_callback' => array('Acme_Rest', 'privileged_permission_callback'),
            'callback' => array('Acme_Rest', 'update_stats'),
        ),
    )
);
