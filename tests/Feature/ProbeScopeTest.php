<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A function that hands its parameter to code outside it: a file it includes,
// or a template it loads with get_template_part().
//
// The summary's probe runs seed each parameter with every kind of taint. They
// used to publish that seed into the shared scope table, so the included file
// saw the parameter tainted whatever the caller passed, and
// `acme_render( 'hello' )` was a high XSS finding in the template. A probe now
// records where its seed would have gone, and each caller publishes what it
// actually passed.

/**
 * @param array<string, string> $files
 */
function scanScopeTree(array $files): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-scope-' . bin2hex(random_bytes(6));

    foreach ($files as $relative => $contents) {
        $path = $directory . '/' . $relative;

        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0o755, true);
        }

        file_put_contents($path, $contents);
    }

    try {
        return (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        foreach (
            new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST,
            ) as $entry
        ) {
            $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
        }

        rmdir($directory);
    }
}

/**
 * @return list<string> rule@file:line for each finding
 */
function scopeFindings(ScanResult $result): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->file . ':' . $finding->line,
        $result->findings->all(),
    );
}

/**
 * @param array<string, string> $plugin the plugin file's body, by name
 *
 * @return array<string, string>
 */
function renderTree(string $calls): array
{
    return [
        'tpl.php' => "<?php\necho \$data;\n",
        'plugin.php' => "<?php\nfunction acme_render( \$data ) {\n    include __DIR__ . '/tpl.php';\n}\n" . $calls,
    ];
}

it('does not report an included template whose every caller passes a literal', function (): void {
    expect(scopeFindings(scanScopeTree(renderTree("acme_render( 'hello' );\n"))))->toBe([]);
});

it('reports an included template a caller passes request data, with the caller in the trace', function (): void {
    $result = scanScopeTree(renderTree("acme_render( \$_GET['x'] );\n"));

    expect(scopeFindings($result))->toBe(['wp.xss.unescaped-output@tpl.php:2']);

    $trace = $result->findings->all()[0]->trace;

    expect($trace[0]->description)->toContain("\$_GET['x']");
    expect($trace[1]->description)->toContain('included file sees it as $data');
});

it('carries a caller\'s taint to the template through a helper that passes it on', function (): void {
    $calls = "function acme_outer( \$v ) {\n    acme_render( \$v );\n}\nacme_outer( 'safe' );\n";

    expect(scopeFindings(scanScopeTree(renderTree($calls))))->toBe([]);
    expect(scopeFindings(scanScopeTree(renderTree($calls . "acme_outer( \$_POST['y'] );\n"))))
        ->toBe(['wp.xss.unescaped-output@tpl.php:2']);
});

it('still reports what the including function itself taints', function (): void {
    $files = [
        'tpl.php' => "<?php\necho \$title;\n",
        'plugin.php' => "<?php\nfunction acme_render( \$data ) {\n    \$title = \$_GET['t'];\n"
            . "    include __DIR__ . '/tpl.php';\n}\nacme_render( 'hello' );\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe(['wp.xss.unescaped-output@tpl.php:2']);
});

/**
 * A theme whose card partial prints $args['title'], loaded from a helper.
 *
 * @return array<string, string>
 */
function cardTheme(string $calls): array
{
    return [
        'style.css' => "/* Theme Name: Acme */\n",
        'template-parts/card.php' => "<?php\necho \$args['title'];\n",
        'functions.php' => "<?php\nfunction acme_card( \$title ) {\n"
            . "    get_template_part( 'template-parts/card', null, array( 'title' => \$title ) );\n}\n" . $calls,
    ];
}

it('does not report a template whose $args every caller fills with a literal', function (): void {
    expect(scopeFindings(scanScopeTree(cardTheme("acme_card( 'Welcome' );\n"))))->toBe([]);
});

it('reports a template a caller fills $args with request data', function (): void {
    expect(scopeFindings(scanScopeTree(cardTheme("acme_card( \$_GET['title'] );\n"))))
        ->toBe(['wp.xss.unescaped-output@template-parts/card.php:2']);
});
