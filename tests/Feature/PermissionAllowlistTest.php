<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A REST route's permission callback runs before its callback. When every
// path that lets a request through checks a parameter against a list of
// literals first, the callback reads one of those values.

/**
 * Whether the route's callback reports SQL injection for a table name built
 * from `objectType`, given this permission callback.
 */
function allowlistReportsTableName(string $permission, string $extra = ''): bool
{
    return allowlistReportsIn(<<<PHP
        <?php
        add_action( 'rest_api_init', function () {
            register_rest_route( 'acme/v1', '/t', array(
                'methods'             => 'POST',
                'callback'            => 'acme_callback',
                'permission_callback' => 'acme_permission',
            ) );
        } );
        {$permission}
        {$extra}
        PHP);
}

/**
 * The same question, for a plugin that registers the route itself. The
 * callback is appended.
 */
function allowlistReportsIn(string $source): bool
{
    $source .= <<<'PHP'

        function acme_callback( $request ) {
            global $wpdb;
            $type = $request->get_param( 'objectType' );
            return $wpdb->get_results( "SELECT 1 FROM {$type}meta" );
        }
        PHP;

    $directory = sys_get_temp_dir() . '/wp-taint-allow-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/plugin.php', $source);

    try {
        $result = (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        unlink($directory . '/plugin.php');
        rmdir($directory);
    }

    foreach ($result->findings->all() as $finding) {
        if ($finding->ruleId === 'wp.sqli.wpdb-query') {
            return true;
        }
    }

    return false;
}

it('credits a strict allowlist that every permitting return is behind', function (): void {
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $type = $request->get_param( 'objectType' );
            if ( ! in_array( $type, array( 'post', 'term' ), true ) ) {
                return false;
            }
            return current_user_can( 'edit_posts' );
        }
        PHP))->toBeFalse();
});

it('reads the request as an array too', function (): void {
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $type = $request['objectType'];
            if ( in_array( $type, array( 'post', 'term' ), true ) ) {
                return true;
            }
            return new WP_Error( 'rest_forbidden', 'No.' );
        }
        PHP))->toBeFalse();
});

it('credits a check that is itself the returned value', function (): void {
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $type = $request->get_param( 'objectType' );
            return in_array( $type, array( 'post', 'term' ), true );
        }
        PHP))->toBeFalse();
});

it('follows a helper the callback returns, called statically', function (): void {
    expect(allowlistReportsTableName(
        'function acme_permission( $request ) { return Acme_Permissions::check( $request ); }',
        <<<'PHP'
            class Acme_Permissions {
                public static function check( $request ) {
                    return self::object_type( $request );
                }
                public static function object_type( $request ) {
                    $type = $request->get_param( 'objectType' );
                    if ( in_array( $type, array( 'post', 'term' ), true ) ) {
                        return true;
                    }
                    return false;
                }
            }
            PHP,
    ))->toBeFalse();
});

it('follows a helper the callback returns, called on $this', function (): void {
    expect(allowlistReportsIn(<<<'PHP'
        <?php
        class Acme_Routes {
            public function register() {
                register_rest_route( 'acme/v1', '/t', array(
                    'methods'             => 'POST',
                    'callback'            => 'acme_callback',
                    'permission_callback' => array( $this, 'check' ),
                ) );
            }
            public function check( $request ) {
                return $this->object_type( $request );
            }
            public function object_type( $request ) {
                $type = $request->get_param( 'objectType' );
                return in_array( $type, array( 'post', 'term' ), true );
            }
        }
        add_action( 'rest_api_init', array( new Acme_Routes(), 'register' ) );
        PHP))->toBeFalse();
});

it('does not credit a return that lets the request through by returning 0', function (): void {
    // WordPress refuses only false, null and a WP_Error.
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $type = $request->get_param( 'objectType' );
            if ( in_array( $type, array( 'post', 'term' ), true ) ) {
                return true;
            }
            return 0;
        }
        PHP))->toBeTrue();
});

it('does not credit a loose in_array()', function (): void {
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $type = $request->get_param( 'objectType' );
            if ( in_array( $type, array( 'post', 'term' ) ) ) {
                return true;
            }
            return false;
        }
        PHP))->toBeTrue();
});

it('does not credit a check on a different parameter', function (): void {
    expect(allowlistReportsTableName(<<<'PHP'
        function acme_permission( $request ) {
            $kind = $request->get_param( 'kind' );
            if ( in_array( $kind, array( 'post', 'term' ), true ) ) {
                return true;
            }
            return false;
        }
        PHP))->toBeTrue();
});
