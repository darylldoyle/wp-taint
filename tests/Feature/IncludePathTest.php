<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// `--include-path`: analyse a tree for its symbols, never report on it.
//
// This is what makes an unmodelled call rare rather than routine. A Composer
// dependency's helper stops being an opaque hole, and so does WordPress core if
// you point at an install — while the reader is never shown a finding in code
// they did not write and cannot fix.

/**
 * @param array<string, string> $files       relative path => contents
 * @param list<string>          $includeDirs relative directories to reference
 */
function scanWithReferences(array $files, array $includeDirs): ScanResult
{
    $root = sys_get_temp_dir() . '/wp-taint-refs-' . bin2hex(random_bytes(6));

    foreach ($files as $relative => $contents) {
        $path = $root . '/' . $relative;
        $parent = dirname($path);

        if (! is_dir($parent)) {
            mkdir($parent, 0o755, true);
        }

        file_put_contents($path, $contents);
    }

    try {
        return (new Scanner(
            testRegistry(),
            new AnalysisOptions(),
            $root . '/app',
            structuralRulesEnabled: true,
            taintGraphPath: null,
            jobs: 1,
            includePaths: array_map(static fn (string $d): string => $root . '/' . $d, $includeDirs),
        ))->scan((new FileFinder())->find([$root . '/app']));
    } finally {
        foreach (array_keys($files) as $relative) {
            @unlink($root . '/' . $relative);
        }

        foreach (array_reverse(glob($root . '/*', GLOB_ONLYDIR) ?: []) as $sub) {
            @rmdir($sub);
        }

        @rmdir($root);
    }
}

/** @return array<string, string> */
function referenceTree(): array
{
    return [
        'app/plugin.php' => <<<'PHP'
            <?php
            function acme_render() {
                echo acme_lib_wrap($_GET['x']);
            }
            function acme_render_safe() {
                echo acme_lib_escape($_GET['x']);
            }
            PHP,
        'vendor/lib.php' => <<<'PHP'
            <?php
            function acme_lib_wrap($v) { return '<i>' . $v . '</i>'; }
            function acme_lib_escape($v) { return esc_html($v); }
            function acme_lib_has_its_own_bug() { echo $_GET['own']; }

            // A structural problem as well as a dataflow one. Suppressing only
            // the dataflow half let WordPress core's own REST controllers get
            // reported when a plugin was scanned with core referenced.
            register_rest_route('lib/v1', '/thing', array(
                'methods'  => 'POST',
                'callback' => 'acme_lib_wrap',
            ));
            PHP,
    ];
}

it('learns what a referenced function does to its argument', function (): void {
    $result = scanWithReferences(referenceTree(), ['vendor']);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('credits a referenced function that escapes', function (): void {
    // Both directions, or this would be a way of manufacturing findings rather
    // than of knowing more.
    $result = scanWithReferences(referenceTree(), ['vendor']);

    $lines = array_map(
        static fn (object $f): int => $f->line,
        $result->findings->all(),
    );

    expect($lines)->not->toContain(6);
});

it('never reports a finding inside a referenced tree', function (): void {
    // vendor/lib.php echoes $_GET['own'] on its own account. That is a real bug
    // and it is not the reader's to fix.
    $result = scanWithReferences(referenceTree(), ['vendor']);

    foreach ($result->findings->all() as $finding) {
        expect($finding->file)->not->toContain('vendor/');
    }
});

it('knows nothing about the tree when it is not referenced', function (): void {
    // The control. Without --include-path the library is an unmodelled call and
    // returns clean, which is the documented behaviour.
    $result = scanWithReferences(referenceTree(), []);

    expect($result->findings)->toBeEmpty();
});

it('counts referenced files separately from scanned ones', function (): void {
    // A run that claims to have scanned 30,000 files when the user pointed it at
    // a two-file plugin is lying about what it looked at.
    $result = scanWithReferences(referenceTree(), ['vendor']);

    expect($result->filesScanned)->toBe(1);
    expect($result->referenceFiles)->toBe(1);
});

it('reads a referenced tree even when it is called vendor', function (): void {
    // The finder skips vendor/ by default when deciding what to report on, and
    // `--include-path=./vendor` is the whole point of the flag. A finder that
    // quietly dropped it would report no findings and give no reason.
    $result = scanWithReferences(referenceTree(), ['vendor']);

    expect($result->referenceFiles)->toBe(1);
});

it('resolves a method inherited from a class in the referenced tree', function (): void {
    // The `extends WP_List_Table` shape: the parent lives in the referenced
    // core, the subclass in the scanned plugin. The hierarchy walk continues
    // into reference-parsed classes, so the inherited table helper resolves and
    // its `$wpdb->prefix` return is accounted for — no unprepared-query noise.
    $result = scanWithReferences([
        'app/table.php' => <<<'PHP'
            <?php
            class Acme_Table extends Acme_Core_Table {
            }

            function acme_rows() {
                global $wpdb;
                $t = Acme_Table::table_name();
                return $wpdb->get_results("SELECT * FROM {$t}");
            }
            PHP,
        'core/class-core-table.php' => <<<'PHP'
            <?php
            class Acme_Core_Table {
                public static function table_name() {
                    global $wpdb;
                    return $wpdb->prefix . 'core_rows';
                }
            }
            PHP,
    ], ['core']);

    expect($result->findings)->toBeEmpty();
});

it('carries taint through a method inherited from the referenced tree', function (): void {
    // The other direction: resolution into the reference tree must not become
    // suppression. The parent's body returns request data, the subclass call in
    // scanned code echoes it, and the finding lands in the scanned file.
    $result = scanWithReferences([
        'app/widget.php' => <<<'PHP'
            <?php
            class Acme_Widget extends Acme_Core_Widget {
            }

            function acme_show() {
                $w = new Acme_Widget();
                echo $w->raw_input();
            }
            PHP,
        'core/class-core-widget.php' => <<<'PHP'
            <?php
            class Acme_Core_Widget {
                public function raw_input() {
                    return $_GET['q'];
                }
            }
            PHP,
    ], ['core']);

    $findings = $result->findings->all();

    expect($findings)->toHaveCount(1);
    expect($findings[0]->ruleId)->toBe('wp.xss.unescaped-output');
    expect($findings[0]->file)->toContain('widget.php');
});
