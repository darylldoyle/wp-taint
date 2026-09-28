<?php

declare(strict_types=1);

// A variable that crosses into another scope keeps its elements under their
// keys: an included file, a template's `$args`, a closure's capture. So the
// template reading `$settings['mode']` sees only what `'mode'` held.

it('keeps an included variable\'s elements apart', function (): void {
    $files = [
        'tpl.php' => "<?php\necho \$settings['mode'];\necho \$settings['title'];\n",
        'plugin.php' => "<?php\nfunction acme_render() {\n"
            . "    \$settings = array( 'title' => \$_GET['t'], 'mode' => 'grid' );\n"
            . "    include __DIR__ . '/tpl.php';\n}\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe(['wp.xss.unescaped-output@tpl.php:3']);
});

it('keeps apart the elements a function builds from its parameter for a file it includes', function (): void {
    $files = [
        'tpl.php' => "<?php\necho \$settings['mode'];\necho \$settings['title'];\n",
        'plugin.php' => "<?php\nfunction acme_render( \$title ) {\n"
            . "    \$settings = array( 'title' => \$title, 'mode' => 'grid' );\n"
            . "    include __DIR__ . '/tpl.php';\n}\n"
            . "acme_render( \$_GET['t'] );\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe(['wp.xss.unescaped-output@tpl.php:3']);
});

it('keeps a template\'s $args nested', function (): void {
    $files = [
        'style.css' => "/* Theme Name: Acme */\n",
        'template-parts/card.php' => "<?php\necho \$args['meta']['id'];\necho \$args['meta']['title'];\n",
        'index.php' => "<?php\nget_template_part( 'template-parts/card', null, "
            . "array( 'meta' => array( 'title' => \$_GET['t'], 'id' => 7 ) ) );\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe(['wp.xss.unescaped-output@template-parts/card.php:3']);
});

it('keeps a captured variable\'s elements apart', function (): void {
    $files = [
        'plugin.php' => "<?php\nfunction acme_boot() {\n"
            . "    \$opts = array( 'title' => \$_GET['t'], 'mode' => 'grid' );\n"
            . "    add_action( 'wp_footer', function () use ( \$opts ) {\n"
            . "        echo \$opts['mode'];\n"
            . "        echo \$opts['title'];\n"
            . "    } );\n}\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe(['wp.xss.unescaped-output@plugin.php:6']);
});

it('lets an assignment in the included file replace the value it was handed', function (): void {
    $files = [
        'tpl.php' => "<?php\n\$settings = array( 'mode' => 'list' );\necho \$settings['mode'];\n",
        'plugin.php' => "<?php\nfunction acme_render() {\n"
            . "    \$settings = array( 'mode' => \$_GET['m'] );\n"
            . "    include __DIR__ . '/tpl.php';\n}\n",
    ];

    expect(scopeFindings(scanScopeTree($files)))->toBe([]);
});
