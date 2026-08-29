<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A loader registration whose component class is declared in a different file
// from the registration. The typed property names the class; the class body —
// where the capability check does or does not live — is elsewhere, so the
// resolution is a key for the whole-scan call graph to walk rather than a set
// of statements from this file's AST.

/**
 * @param array<string, string> $files relative path => contents
 */
function scanLoaderProject(array $files): ScanResult
{
    $root = sys_get_temp_dir() . '/wp-taint-loader-' . bin2hex(random_bytes(6));

    foreach ($files as $relative => $contents) {
        $path = $root . '/' . $relative;

        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0o755, true);
        }

        file_put_contents($path, $contents);
    }

    try {
        return (new Scanner(testRegistry(), new AnalysisOptions(), $root))
            ->scan((new FileFinder())->find([$root]));
    } finally {
        foreach (array_keys($files) as $relative) {
            @unlink($root . '/' . $relative);
        }

        @rmdir($root);
    }
}

const LOADER_PLUGIN = <<<'PHP_SOURCE'
<?php
class Acme_Loader {
    public array $actions = [];
    public function add_action( string $hook, object $component, string $callback ): void {
        $this->actions[] = [ $hook, $component, $callback ];
    }
}
class Acme_Loader_Plugin {
    protected Acme_Admin_Component $admin;
    protected Acme_Loader $loader;
    public function __construct( Acme_Admin_Component $admin ) {
        $this->admin  = $admin;
        $this->loader = new Acme_Loader();
        $this->loader->add_action( 'wp_ajax_acme_save', $this->admin, 'handle' );
    }
}
PHP_SOURCE;

it('reports a loader-registered handler whose cross-file component checks nothing', function (): void {
    $result = scanLoaderProject([
        'plugin.php' => LOADER_PLUGIN,
        'component.php' => <<<'PHP_SOURCE'
        <?php
        class Acme_Admin_Component {
            public function handle(): void {
                update_option( 'acme_from_loader', 1 );
            }
        }
        PHP_SOURCE,
    ]);

    $rules = array_map(
        static fn ($finding): string => $finding->ruleId,
        $result->findings->all(),
    );

    expect($rules)->toContain('wp.authz.ajax-missing-check');
});

it('stays silent when the cross-file component checks a capability', function (): void {
    $result = scanLoaderProject([
        'plugin.php' => LOADER_PLUGIN,
        'component.php' => <<<'PHP_SOURCE'
        <?php
        class Acme_Admin_Component {
            public function handle(): void {
                check_ajax_referer( 'acme' );
                if ( ! current_user_can( 'manage_options' ) ) {
                    wp_die();
                }
                update_option( 'acme_from_loader', 1 );
            }
        }
        PHP_SOURCE,
    ]);

    expect($result->findings->all())->toBe([]);
});
