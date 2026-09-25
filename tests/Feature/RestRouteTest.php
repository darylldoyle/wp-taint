<?php

declare(strict_types=1);

// A REST route's schema and permission callback are fixed where the route is
// registered, and WordPress applies both before the route's callback runs. So
// what they do is credited, where a filter callback never is: nothing can take
// them off again at runtime.
//
// Every callable form is followed, because the route table resolves callbacks
// through the same CallableResolver the dataflow uses everywhere else.

/** @return list<string> */
function restRules(string $code): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . ' ' . $finding->severity->value . ' L' . $finding->line,
        scanCode($code)->findings->all(),
    );
}

/**
 * One GET route on `acme_cb`, public, with `$args` as its schema.
 */
function restRouteWithArgs(string $args, string $callback, string $extra = ''): string
{
    return <<<PHP
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'GET',
            'callback' => 'acme_cb',
            'permission_callback' => '__return_true',
            'args' => {$args},
        ) );
        {$callback}
        {$extra}
        PHP;
}

/**
 * One route on `acme_delete`, guarded by `$permission`, that deletes the post
 * the request names.
 */
function restDeleteRoute(string $permission, string $extra = ''): string
{
    return <<<PHP
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'DELETE',
            'callback' => 'acme_delete',
            'permission_callback' => {$permission},
        ) );
        function acme_delete( \$request ) { wp_delete_post( (int) \$request['id'] ); }
        {$extra}
        PHP;
}

it('reads $request[ key ] as the REST parameter it is', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'GET', 'callback' => 'acme_cb', 'permission_callback' => '__return_true',
        ) );
        function acme_cb( WP_REST_Request $request ) { echo $request['name']; }
        PHP))->toBe(['wp.xss.unescaped-output high L5']);
});

it('reads $request[ key ] on a typed request outside a route callback', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        function acme_helper( WP_REST_Request $request ) { echo $request['name']; }
        PHP))->toBe(['wp.xss.unescaped-output high L2']);
});

it('credits a sanitize_callback written in any callable form', function (string $callback, string $extra): void {
    expect(restRules(restRouteWithArgs(
        "array( 'name' => array( 'sanitize_callback' => {$callback} ) )",
        'function acme_cb( $request ) { echo $request[\'name\']; echo $request->get_param( \'name\' ); }',
        $extra,
    )))->toBe([]);
})->with([
    'a function name' => ["'esc_html'", ''],
    'a user function' => ["'acme_clean'", 'function acme_clean( $v ) { return esc_html( $v ); }'],
    'Class::method' => [
        "'Acme_Clean::run'",
        'class Acme_Clean { public static function run( $v ) { return esc_html( $v ); } }',
    ],
    'a class and method pair' => [
        "array( 'Acme_Clean', 'run' )",
        'class Acme_Clean { public static function run( $v ) { return esc_html( $v ); } }',
    ],
    'a closure' => ['function ( $v ) { return esc_html( $v ); }', ''],
    'an arrow function' => ['fn ( $v ) => esc_html( $v )', ''],
]);

it('credits a sanitize_callback on a method of the registering class', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        class Acme_Api {
            public function register() {
                register_rest_route( 'acme/v1', '/x', array(
                    'methods' => 'GET', 'callback' => array( $this, 'show' ), 'permission_callback' => '__return_true',
                    'args' => array( 'name' => array( 'sanitize_callback' => array( $this, 'clean' ) ) ),
                ) );
            }
            public function clean( $v ) { return esc_html( $v ); }
            public function show( $request ) { echo $request['name']; }
        }
        PHP))->toBe([]);
});

it('does not credit a sanitize_callback that does not sanitise for the sink', function (): void {
    expect(restRules(restRouteWithArgs(
        "array( 'name' => array( 'sanitize_callback' => 'trim' ) )",
        'function acme_cb( $request ) { echo $request[\'name\']; }',
    )))->toBe(['wp.xss.unescaped-output high L8']);
});

it('applies core\'s schema default when a type is declared without a sanitize_callback', function (): void {
    expect(restRules(restRouteWithArgs(
        <<<'PHP'
            array(
                'page' => array( 'type' => 'integer' ),
                'label' => array( 'type' => 'string', 'format' => 'text-field' ),
                'mode' => array( 'type' => 'string', 'enum' => array( 'a', 'b' ) ),
            )
            PHP,
        'function acme_cb( $request ) { echo $request[\'page\']; echo $request[\'label\']; echo $request[\'mode\']; }',
    )))->toBe([]);
});

it('applies no schema default for an empty sanitize_callback or a plain string type', function (): void {
    expect(restRules(restRouteWithArgs(
        <<<'PHP'
            array(
                'page' => array( 'type' => 'integer', 'sanitize_callback' => null ),
                'name' => array( 'type' => 'string' ),
            )
            PHP,
        'function acme_cb( $request ) { echo $request[\'page\']; echo $request[\'name\']; }',
    )))->toHaveCount(2);
});

it('sanitises only as far as every route to the callback does', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/a', array(
            'methods' => 'GET', 'callback' => 'acme_cb', 'permission_callback' => '__return_true',
            'args' => array( 'name' => array( 'sanitize_callback' => 'esc_html' ) ),
        ) );
        register_rest_route( 'acme/v1', '/b', array(
            'methods' => 'GET', 'callback' => 'acme_cb', 'permission_callback' => '__return_true',
        ) );
        function acme_cb( $request ) { echo $request['name']; }
        PHP))->toBe(['wp.xss.unescaped-output high L9']);
});

it('merges the shared args into every route definition', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'args' => array( 'name' => array( 'sanitize_callback' => 'esc_html' ) ),
            array( 'methods' => 'GET', 'callback' => 'acme_cb', 'permission_callback' => '__return_true' ),
        ) );
        function acme_cb( $request ) { echo $request['name']; }
        PHP))->toBe([]);
});

it('credits a permission callback that entitles the caller', function (string $permission, string $extra): void {
    expect(restRules(restDeleteRoute($permission, $extra)))->toBe([]);
})->with([
    'an object capability with the id' => [
        "function ( \$r ) { return current_user_can( 'delete_post', \$r['id'] ); }",
        '',
    ],
    'a site capability' => ["function () { return current_user_can( 'manage_options' ); }", ''],
    'a guard clause' => [
        "'acme_can'",
        <<<'PHP'
            function acme_can( $r ) {
                if ( ! current_user_can( 'manage_options' ) ) {
                    return new WP_Error( 'no' );
                }
                return true;
            }
            PHP,
    ],
    'a conjunction' => ["fn ( \$r ) => current_user_can( 'delete_post', \$r['id'] ) && is_user_logged_in()", ''],
]);

it('does not credit a permission callback that does not entitle the caller', function (string $permission): void {
    expect(restRules(restDeleteRoute($permission)))->toContain('wp.authz.object-id-from-request high L7');
})->with([
    'a role capability' => ["function () { return current_user_can( 'edit_posts' ); }"],
    '__return_true' => ["'__return_true'"],
    'a login check' => ["'is_user_logged_in'"],
]);

it('does not credit a permission callback when another route shares the callback without one', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/a', array(
            'methods' => 'GET', 'callback' => 'acme_delete',
            'permission_callback' => function () { return current_user_can( 'manage_options' ); },
        ) );
        register_rest_route( 'acme/v1', '/b', array(
            'methods' => 'GET', 'callback' => 'acme_delete', 'permission_callback' => '__return_true',
        ) );
        function acme_delete( $request ) { wp_delete_post( (int) $request['id'] ); }
        PHP))->toContain('wp.authz.object-id-from-request high L9');
});

it('credits the route\'s permission callback in a helper the callback hands the id to', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'DELETE', 'callback' => 'acme_delete',
            'permission_callback' => function () { return current_user_can( 'manage_options' ); },
        ) );
        function acme_delete( $request ) { acme_remove( (int) $request['id'] ); }
        function acme_remove( $id ) { wp_delete_post( $id ); }
        PHP))->toBe([]);
});

it('still reports the helper when the route is public', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'GET', 'callback' => 'acme_delete', 'permission_callback' => '__return_true',
        ) );
        function acme_delete( $request ) { acme_remove( (int) $request['id'] ); }
        function acme_remove( $id ) { wp_delete_post( $id ); }
        PHP))->toContain('wp.authz.object-id-from-request high L6');
});

it('credits a permission callback whose guard is a compound condition', function (): void {
    expect(restRules(restDeleteRoute("'acme_can'", <<<'PHP'
        function acme_can() {
            if ( ! current_user_can( 'manage_options' ) || empty( $GLOBALS['acme_ready'] ) ) {
                return new WP_Error( 'no' );
            }
            return true;
        }
        PHP)))->toBe([]);
});

it('does not credit a compound guard on a role capability', function (): void {
    expect(restRules(restDeleteRoute("'acme_can'", <<<'PHP'
        function acme_can() {
            if ( ! current_user_can( 'edit_posts' ) || empty( $GLOBALS['acme_ready'] ) ) {
                return new WP_Error( 'no' );
            }
            return true;
        }
        PHP)))->toContain('wp.authz.object-id-from-request high L7');
});

it('treats returning a value just proved to be a WP_Error as a refusal', function (): void {
    expect(restRules(restDeleteRoute("'acme_can'", <<<'PHP'
        function acme_can( $request ) {
            $review = acme_find( $request['id'] );
            if ( is_wp_error( $review ) ) {
                return $review;
            }
            if ( ! current_user_can( 'delete_post', $request['id'] ) ) {
                return false;
            }
            return true;
        }
        PHP)))->toBe([]);
});

it('credits a compound guard in the handler itself', function (): void {
    expect(restRules(<<<'PHP'
        <?php
        function acme_handler() {
            if ( ! current_user_can( 'manage_options' ) || ! isset( $_POST['id'] ) ) {
                wp_die();
            }
            wp_delete_post( (int) $_POST['id'] );
        }
        add_action( 'wp_ajax_acme', 'acme_handler' );
        PHP))->not->toContain('wp.authz.object-id-from-request high L6');
});

it('carries a route\'s entitlement into what the callback calls', function (string $permission, bool $reported): void {
    $findings = restRules(<<<PHP
        <?php
        register_rest_route( 'acme/v1', '/x', array(
            'methods' => 'POST', 'callback' => fn ( \$r ) => ( new Acme_Api() )->update( \$r ),
            'permission_callback' => {$permission},
        ) );
        class Acme_Api {
            public function update( \$request ) { wp_delete_post( (int) \$request->get_param( 'id' ) ); }
        }
        PHP);

    expect(in_array('wp.authz.object-id-from-request high L7', $findings, true))->toBe($reported);
})->with([
    'entitled' => ["fn () => current_user_can( 'manage_options' )", false],
    'public' => ["'__return_true'", true],
]);
