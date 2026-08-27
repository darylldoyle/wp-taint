<?php

/**
 * The same omission with an array callback on $this.
 */

class Acme_Rest_Controller
{
    public function register_routes()
    {
        register_rest_route('acme/v1', '/export', [ // wp-taint-expect wp.authz.rest-missing-permission-callback authz
            'methods' => 'GET',
            'callback' => [$this, 'export'],
        ]);
    }

    public function export($request)
    {
        return ['ok' => true];
    }
}
