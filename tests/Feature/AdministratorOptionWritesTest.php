<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// An option write records what it stored, and a later get_option() of the
// same name reads it back. Stored data carries no `url`, so only the write can
// make "save a URL, then redirect to it" a finding. A write only an
// administrator can make stores nothing. Administrators are trusted, and what
// they saved is theirs to redirect to. Anyone else's write stores everything.

/**
 * The redirect findings in a plugin that saves its `acme` option as `$save`
 * does, and redirects to the `target` a later request reads back.
 *
 * The read comes first, so a finding is at line 4.
 *
 * @return list<string>
 */
function redirectsToSavedTarget(string $save): array
{
    return redirectFindingsIn("<?php\n" . <<<'PHP'
        function acme_go() {
            $settings = get_option( 'acme' );
            wp_redirect( $settings['target'] );
            exit;
        }

        PHP . $save);
}

/**
 * The same, for a plugin that saves the target as a single value in
 * `acme_target`. A finding is at line 3.
 *
 * @return list<string>
 */
function redirectsToSavedValue(string $save): array
{
    return redirectFindingsIn("<?php\n" . <<<'PHP'
        function acme_go() {
            wp_redirect( get_option( 'acme_target' ) );
            exit;
        }

        PHP . $save);
}

/**
 * @param string|array<string, string> $source one file, or several by name
 *
 * @return list<string>
 */
function redirectFindingsIn(string|array $source): array
{
    if (is_string($source)) {
        $result = scanCode($source);
    } else {
        $directory = sys_get_temp_dir() . '/wp-taint-admin-options-' . bin2hex(random_bytes(6));
        mkdir($directory . '/inc', 0o755, true);

        foreach ($source as $name => $contents) {
            file_put_contents($directory . '/' . $name, $contents);
        }

        try {
            $result = (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
                ->scan((new FileFinder())->find([$directory]));
        } finally {
            foreach (array_keys($source) as $name) {
                unlink($directory . '/' . $name);
            }

            rmdir($directory . '/inc');
            rmdir($directory);
        }
    }

    return array_values(array_filter(
        findingSignatures($result),
        static fn (string $signature): bool => str_starts_with($signature, 'wp.redirect.'),
    ));
}

it('reports an array saved in an unauthenticated handler', function (string $hook): void {
    expect(redirectsToSavedTarget(<<<PHP
        add_action( '{$hook}', 'acme_save' );
        function acme_save() {
            update_option( 'acme', array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        }
        PHP))->toBe(['wp.redirect.open-redirect@4']);
})->with(['wp_ajax_nopriv_acme_save', 'admin_post_nopriv_acme_save']);

it('reports an array whose key the request chose', function (): void {
    expect(redirectFindingsIn(<<<'PHP'
        <?php
        function acme_go() {
            foreach ( get_option( 'acme' ) as $target => $enabled ) {
                wp_redirect( $target );
            }
        }
        add_action( 'wp_ajax_nopriv_acme_save', function () {
            update_option( 'acme', array( wp_unslash( $_POST['target'] ) => true ) );
        } );
        PHP))->toBe(['wp.redirect.open-redirect@4']);
});

it('stores nothing from an array saved behind a manage_options check', function (): void {
    expect(redirectsToSavedTarget(<<<'PHP'
        add_action( 'wp_ajax_acme_save', 'acme_save' );
        function acme_save() {
            check_ajax_referer( 'acme-save' );
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }
            update_option( 'acme', array( 'target' => wp_unslash( $_POST['target'] ) ) );
        }
        PHP))->toBe([]);
});

it('stores nothing from an array saved on a manage_options admin page', function (string $register): void {
    expect(redirectsToSavedTarget(<<<PHP
        add_action( 'admin_menu', function () {
            {$register}
        } );
        function acme_settings_page() {
            if ( isset( \$_POST['target'] ) ) {
                check_admin_referer( 'acme-settings' );
                update_option( 'acme', array( 'target' => wp_unslash( \$_POST['target'] ) ) );
            }
        }
        PHP))->toBe([]);
})->with([
    "add_menu_page( 'Acme', 'Acme', 'manage_options', 'acme', 'acme_settings_page' );",
    "add_submenu_page( 'acme', 'Settings', 'Settings', 'manage_options', 'acme-settings', 'acme_settings_page' );",
    "add_options_page( 'Acme', 'Acme', 'manage_options', 'acme', 'acme_settings_page' );",
]);

it('reports an array saved behind a nonce check alone', function (): void {
    // Any logged-in user holds a valid nonce for every form they can see.
    expect(redirectsToSavedTarget(<<<'PHP'
        add_action( 'admin_post_acme_save', 'acme_save' );
        function acme_save() {
            check_admin_referer( 'acme-save' );
            update_option( 'acme', array( 'target' => wp_unslash( $_POST['target'] ) ) );
        }
        PHP))->toBe(['wp.redirect.open-redirect@4']);
});

it('reports an array saved behind a capability an author holds', function (string $check): void {
    expect(redirectsToSavedTarget(<<<PHP
        add_action( 'wp_ajax_acme_save', 'acme_save' );
        function acme_save() {
            if ( ! {$check} ) {
                wp_die();
            }
            update_option( 'acme', array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        }
        PHP))->toBe(['wp.redirect.open-redirect@4']);
})->with([
    "current_user_can( 'edit_posts' )",
    "current_user_can( 'upload_files' )",
    "current_user_can( 'edit_post', absint( \$_POST['post'] ) )",
]);

it('judges a check by what the call reaches, not by its name', function (string $check, array $expected): void {
    // LiteSpeed Cache guards its front-end optimiser with
    // `$this->cls( 'Router' )->can_optm()`, which lets every visitor through.
    expect(redirectsToSavedTarget(<<<PHP
        class Acme_Router {
            public function can_optimize() {
                return ! is_admin();
            }
            public function can_manage() {
                return current_user_can( 'manage_options' );
            }
            public static function can_see() {
                return true;
            }
        }
        add_action( 'template_redirect', function () {
            \$router = acme_router();
            if ( ! {$check} ) {
                return;
            }
            update_option( 'acme', array( 'target' => wp_unslash( \$_GET['target'] ) ) );
        } );
        PHP))->toBe($expected);
})->with([
    'a method named like a check' => ['$router->can_optimize()', ['wp.redirect.open-redirect@4']],
    'a method that checks a capability' => ['$router->can_manage()', []],
    'a static helper named like a check' => ['Acme_Router::can_see()', ['wp.redirect.open-redirect@4']],
]);

it('reports an array saved on an admin page an author can open', function (): void {
    expect(redirectsToSavedTarget(<<<'PHP'
        add_action( 'admin_menu', function () {
            add_menu_page( 'Acme', 'Acme', 'edit_posts', 'acme', 'acme_settings_page' );
        } );
        function acme_settings_page() {
            update_option( 'acme', array( 'target' => wp_unslash( $_POST['target'] ) ) );
        }
        PHP))->toBe(['wp.redirect.open-redirect@4']);
});

it('keeps the escaping ledger out of an array it stores', function (): void {
    // The stored `escaped` would read back through the filterable
    // get_option() as escaping voided, on a line the output rule owns.
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_show() {
            $settings = get_option( 'acme' );
            echo $settings['title'];
        }
        add_action( 'wp_ajax_nopriv_acme_save', function () {
            update_option( 'acme', array( 'title' => esc_html( wp_unslash( $_POST['title'] ) ) ) );
        } );
        PHP)))->toContain('wp.xss.unescaped-output@4')
        ->not->toContain('wp.xss.escape-voided@4');
});

it('keeps the escaping ledger out of what a helper stores', function (): void {
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_show() {
            echo get_option( 'acme_title' );
        }
        function acme_store( $title ) {
            update_option( 'acme_title', $title );
        }
        add_action( 'wp_ajax_nopriv_acme_save', function () {
            acme_store( esc_html( wp_unslash( $_POST['title'] ) ) );
        } );
        PHP)))->toContain('wp.xss.unescaped-output@3')
        ->not->toContain('wp.xss.escape-voided@3');
});

it('judges a single value by who saved it', function (string $save, array $expected): void {
    expect(redirectsToSavedValue($save))->toBe($expected);
})->with([
    'an unauthenticated handler' => [
        <<<'PHP'
            add_action( 'wp_ajax_nopriv_acme_save', function () {
                update_option( 'acme_target', wp_unslash( $_POST['target'] ) );
            } );
            PHP,
        ['wp.redirect.open-redirect@3'],
    ],
    'a manage_options check' => [
        <<<'PHP'
            add_action( 'wp_ajax_acme_save', function () {
                if ( current_user_can( 'manage_options' ) ) {
                    update_option( 'acme_target', wp_unslash( $_POST['target'] ) );
                }
            } );
            PHP,
        [],
    ],
    'a REST route open to anyone' => [
        <<<'PHP'
            add_action( 'rest_api_init', function () {
                register_rest_route( 'acme/v1', '/target', array(
                    'methods'             => 'POST',
                    'callback'            => 'acme_route',
                    'permission_callback' => '__return_true',
                ) );
            } );
            function acme_route( $request ) {
                update_option( 'acme_target', $request->get_param( 'target' ) );
            }
            PHP,
        ['wp.redirect.open-redirect@3'],
    ],
    'a REST route for administrators' => [
        <<<'PHP'
            add_action( 'rest_api_init', function () {
                register_rest_route( 'acme/v1', '/target', array(
                    'methods'             => 'POST',
                    'callback'            => 'acme_route',
                    'permission_callback' => function () {
                        return current_user_can( 'manage_options' );
                    },
                ) );
            } );
            function acme_route( $request ) {
                update_option( 'acme_target', $request->get_param( 'target' ) );
            }
            PHP,
        [],
    ],
    'a REST route for authors' => [
        <<<'PHP'
            add_action( 'rest_api_init', function () {
                register_rest_route( 'acme/v1', '/target', array(
                    'methods'             => 'POST',
                    'callback'            => 'acme_route',
                    'permission_callback' => function () {
                        return current_user_can( 'edit_posts' );
                    },
                ) );
            } );
            function acme_route( $request ) {
                update_option( 'acme_target', $request->get_param( 'target' ) );
            }
            PHP,
        ['wp.redirect.open-redirect@3'],
    ],
]);

it('judges settings saved through a REST route by its permission callback', function (
    string $permission,
    array $expected,
): void {
    // Redirection's shape: the option name is a class constant, the settings
    // save one helper down from the route's callback, and the permission
    // callback checks a capability that a filter chooses.
    expect(redirectFindingsIn(<<<PHP
        <?php
        function acme_go() {
            \$options = Acme_Options::get();
            wp_redirect( \$options['target'] );
            exit;
        }
        class Acme_Options {
            const OPTION_KEY = 'acme_options';
            public static function get() {
                return get_option( self::OPTION_KEY );
            }
            public static function save( array \$settings ) {
                update_option( self::OPTION_KEY, \$settings );
            }
        }
        class Acme_Capabilities {
            public static function has_access( \$cap ) {
                return current_user_can( apply_filters( 'acme_capability_check', 'manage_options', \$cap ) );
            }
        }
        class Acme_Api_Settings {
            public function __construct() {
                register_rest_route( 'acme/v1', '/setting', array(
                    'methods'             => 'POST',
                    'callback'            => array( \$this, 'route_save_settings' ),
                    'permission_callback' => {$permission},
                ) );
            }
            public function permission_callback_manage( \$request ) {
                return Acme_Capabilities::has_access( 'acme_options_manage' );
            }
            public function route_save_settings( \$request ) {
                Acme_Options::save( \$request->get_params() );
            }
        }
        PHP))->toBe($expected);
})->with([
    'a capability helper' => ["array( \$this, 'permission_callback_manage' )", []],
    'no check at all' => ["'__return_true'", ['wp.redirect.open-redirect@4']],
]);

it('judges a helper that saves by every caller it has', function (string $callers, array $expected): void {
    expect(redirectsToSavedTarget(<<<PHP
        function acme_save( \$settings ) {
            update_option( 'acme', \$settings );
        }
        add_action( 'admin_menu', function () {
            add_options_page( 'Acme', 'Acme', 'manage_options', 'acme', 'acme_settings_page' );
        } );
        function acme_settings_page() {
            acme_save( array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        }
        add_action( 'wp_ajax_acme_save', function () {
            if ( ! current_user_can( 'manage_options' ) ) {
                wp_die();
            }
            acme_save( array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        } );
        {$callers}
        PHP))->toBe($expected);
})->with([
    'only administrators call it' => ['', []],
    'an unauthenticated handler calls it too' => [
        <<<'PHP'
            add_action( 'wp_ajax_nopriv_acme_save', function () {
                acme_save( array( 'target' => wp_unslash( $_POST['target'] ) ) );
            } );
            PHP,
        ['wp.redirect.open-redirect@4'],
    ],
]);

it('judges a helper that reads the request itself by every path to it', function (
    string $callers,
    array $expected,
): void {
    // The helper's own body has no check. Two levels up, one caller is a
    // manage_options page and the other checks first.
    expect(redirectsToSavedTarget(<<<PHP
        function acme_save() {
            update_option( 'acme', array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        }
        function acme_process() {
            acme_save();
        }
        add_action( 'admin_menu', function () {
            add_submenu_page( 'tools.php', 'Acme', 'Acme', 'manage_options', 'acme', 'acme_settings_page' );
        } );
        function acme_settings_page() {
            acme_process();
        }
        add_action( 'wp_ajax_acme_save', 'acme_ajax_save' );
        function acme_ajax_save() {
            if ( current_user_can( 'manage_options' ) ) {
                acme_process();
            }
        }
        {$callers}
        PHP))->toBe($expected);
})->with([
    'only administrators reach it' => ['', []],
    'a front-end hook reaches it too' => [
        "add_action( 'template_redirect', 'acme_process' );",
        ['wp.redirect.open-redirect@4'],
    ],
    'a handler reaches it before its check' => [
        <<<'PHP'
            add_action( 'wp_ajax_acme_import', function () {
                acme_process();
                if ( ! current_user_can( 'manage_options' ) ) {
                    wp_die();
                }
            } );
            PHP,
        ['wp.redirect.open-redirect@4'],
    ],
]);

it('judges an included file by the page that includes it', function (string $capability, array $expected): void {
    // WP File Manager saves its preferences in inc/root.php, which only the
    // callback of a manage_options page includes.
    expect(redirectFindingsIn([
        'plugin.php' => <<<PHP
            <?php
            function acme_go() {
                \$settings = get_option( 'acme' );
                wp_redirect( \$settings['target'] );
                exit;
            }
            add_action( 'admin_menu', function () {
                add_menu_page( 'Acme', 'Acme', '{$capability}', 'acme', 'acme_root' );
            } );
            function acme_root() {
                include __DIR__ . '/inc/root.php';
            }
            PHP,
        'inc/root.php' => <<<'PHP'
            <?php
            if ( isset( $_POST['submit'] ) && wp_verify_nonce( sanitize_text_field( $_POST['nonce'] ), 'acme_root' ) ) {
                update_option( 'acme', array( 'target' => $_POST['target'] ) );
            }
            PHP,
    ]))->toBe($expected);
})->with([
    'manage_options' => ['manage_options', []],
    'read' => ['read', ['wp.redirect.open-redirect@4']],
]);

it('treats a hook callback as an entry point, whoever fires the hook', function (
    string $callback,
    array $expected,
): void {
    // The plugin fires `acme_saved` only from its own settings page, and the
    // scan cannot tell that apart from a hook WordPress fires as well. What
    // the dispatch hands the callback is judged where it is fired.
    expect(redirectsToSavedTarget(<<<PHP
        add_action( 'admin_menu', function () {
            add_options_page( 'Acme', 'Acme', 'manage_options', 'acme', 'acme_settings_page' );
        } );
        function acme_settings_page() {
            do_action( 'acme_saved', array( 'target' => wp_unslash( \$_POST['target'] ) ) );
        }
        add_action( 'acme_saved', 'acme_store' );
        {$callback}
        PHP))->toBe($expected);
})->with([
    'saving what the dispatch hands it' => [
        "function acme_store( \$settings ) { update_option( 'acme', \$settings ); }",
        [],
    ],
    'saving what it reads itself' => [
        "function acme_store() { update_option( 'acme', array( 'target' => wp_unslash( \$_POST['target'] ) ) ); }",
        ['wp.redirect.open-redirect@4'],
    ],
]);

it('treats functions that only call each other as reachable by anyone', function (): void {
    // Nothing in the scan calls the pair, so something outside it does.
    expect(redirectsToSavedTarget(<<<'PHP'
        function acme_save( $attempts ) {
            if ( $attempts > 0 ) {
                acme_retry( $attempts - 1 );
            }
            update_option( 'acme', array( 'target' => wp_unslash( $_POST['target'] ) ) );
        }
        function acme_retry( $attempts ) {
            acme_save( $attempts );
        }
        PHP))->toBe(['wp.redirect.open-redirect@4']);
});
