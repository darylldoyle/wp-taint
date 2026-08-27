<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// The theme shape.
//
// PHP includes share the includer's variable scope, which is why a template can
// echo a variable it never declared. It is also the change most likely to
// invent false positives, because it connects request data to files that have
// never been analysed in context — so the safe cases here matter as much as the
// unsafe ones.

/**
 * @param array<string, string> $files relative path => contents
 */
function scanTree(array $files, ?AnalysisOptions $options = null): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-include-' . bin2hex(random_bytes(6));

    foreach ($files as $relative => $contents) {
        $path = $directory . '/' . $relative;
        $parent = dirname($path);

        if (! is_dir($parent)) {
            mkdir($parent, 0o755, true);
        }

        file_put_contents($path, $contents);
    }

    try {
        return (new Scanner(
            testRegistry(),
            $options ?? new AnalysisOptions(),
            $directory,
        ))->scan((new FileFinder())->find([$directory]));
    } finally {
        foreach (array_keys($files) as $relative) {
            @unlink($directory . '/' . $relative);
        }

        foreach (array_reverse(glob($directory . '/*', GLOB_ONLYDIR) ?: []) as $sub) {
            @rmdir($sub);
        }

        @rmdir($directory);
    }
}

it('carries a variable into the template that echoes it', function (): void {
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            include __DIR__ . '/parts/header.php';
            PHP,
        'parts/header.php' => <<<'PHP'
            <?php
            echo $title;
            PHP,
    ]);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@2']);
});

it('credits a template that escapes', function (): void {
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            include __DIR__ . '/parts/header.php';
            PHP,
        'parts/header.php' => <<<'PHP'
            <?php
            echo esc_html($title);
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
});

it('resolves a path built from a constant', function (): void {
    // How WordPress actually writes it. Without constant resolution, path
    // folding stops at the first name it meets.
    $result = scanTree([
        'plugin.php' => <<<'PHP'
            <?php
            define('ACME_DIR', __DIR__ . '/');
            $slug = $_GET['slug'];
            require_once ACME_DIR . 'views/list.php';
            PHP,
        'views/list.php' => <<<'PHP'
            <?php
            echo $slug;
            PHP,
    ]);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@2']);
});

it('carries a variable back out of the included file', function (): void {
    // Both directions. The included file's assignments are visible afterwards,
    // which is how a WordPress config partial works.
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            include __DIR__ . '/config.php';
            echo $acme_setting;
            PHP,
        'config.php' => <<<'PHP'
            <?php
            $acme_setting = $_GET['setting'];
            PHP,
    ]);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('does not connect two templates that never meet', function (): void {
    // The precision that matters. `$title` is tainted in one file and echoed in
    // another, and nothing includes anything, so there is no flow.
    $result = scanTree([
        'one.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            PHP,
        'two.php' => <<<'PHP'
            <?php
            echo $title;
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
});

it('stops at an include it cannot resolve', function (): void {
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            include $_GET['template'] . '.php';
            PHP,
    ]);

    // The include is a path-traversal sink in its own right, which is reported.
    // What must not happen is a claim about what the included file did.
    expect(findingSignatures($result))->toBe(['wp.lfi.dynamic-include@3']);
});

it('terminates on an include cycle', function (): void {
    $result = scanTree([
        'a.php' => <<<'PHP'
            <?php
            $value = $_GET['v'];
            include __DIR__ . '/b.php';
            PHP,
        'b.php' => <<<'PHP'
            <?php
            include __DIR__ . '/a.php';
            echo $value;
            PHP,
    ]);

    expect($result->warnings)->toBeEmpty();
    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('can be turned off', function (): void {
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            include __DIR__ . '/parts/header.php';
            PHP,
        'parts/header.php' => <<<'PHP'
            <?php
            echo $title;
            PHP,
    ], new AnalysisOptions(followIncludes: false));

    expect($result->findings)->toBeEmpty();
});

it('does not pass one includer variables through a shared partial to another', function (): void {
    // The failure that nearly shipped. With one scope entry per file, a variable
    // pushed *in* by one includer came straight back *out* to every other, and a
    // partial neither of them wrote became a channel between them.
    //
    // Jetpack's constants.php was handing out $page_routes, a name it never
    // mentions, and twenty findings followed.
    $result = scanTree([
        'shared.php' => <<<'PHP'
            <?php
            $acme_version = '1.0';
            PHP,
        'tainted.php' => <<<'PHP'
            <?php
            $payload = $_GET['payload'];
            require __DIR__ . '/shared.php';
            PHP,
        'clean.php' => <<<'PHP'
            <?php
            require __DIR__ . '/shared.php';
            echo $payload;
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
});

it('still carries what the partial does assign', function (): void {
    $result = scanTree([
        'shared.php' => <<<'PHP'
            <?php
            $acme_mode = $_GET['mode'];
            PHP,
        'index.php' => <<<'PHP'
            <?php
            require __DIR__ . '/shared.php';
            echo $acme_mode;
            PHP,
    ]);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('traces an include-seeded finding back to its source', function (): void {
    // A trace that begins "$title was in scope at the include that loaded this
    // file" and stops there tells a reviewer nothing about whether the value is
    // attacker controlled, and a finding a reviewer cannot judge is one they
    // learn to ignore. The property map solved the identical problem by
    // splicing the write's trace in ahead of the read.
    $result = scanTree([
        'index.php' => <<<'PHP'
            <?php
            $title = $_GET['title'];
            include __DIR__ . '/parts/header.php';
            PHP,
        'parts/header.php' => <<<'PHP'
            <?php
            echo $title;
            PHP,
    ]);

    $trace = $result->findings->all()[0]->trace;
    $descriptions = array_map(static fn (object $step): string => $step->description, $trace);

    expect($descriptions[0])->toContain('Tainted by superglobal $_GET');
    expect($trace[0]->file)->toContain('index.php');
    expect(end($descriptions))->toContain('Reaches echo');
});
