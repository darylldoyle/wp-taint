<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\AnalysisOptions;

// `get_template_part()` and the template hierarchy.
//
// The idiomatic form in a theme, and the half of the picture that `include`
// following does not cover. The precision point is that a template loaded this
// way is *not* an include: it runs inside load_template(), so it sees the
// globals and the $args array and never the caller's locals.

/** @return array<string, string> */
function themeTree(): array
{
    return [
        // A theme marker, so the resolver can find the root a slug is relative
        // to even when the scan root is somewhere above it.
        'style.css' => "/* Theme Name: Acme */\n",
        'index.php' => <<<'PHP'
            <?php
            $acme_local = $_GET['leak'];
            get_template_part('template-parts/content', 'page', array('title' => $_GET['title']));
            get_header('shop');
            PHP,
        'template-parts/content-page.php' => <<<'PHP'
            <?php
            echo $args['title'];
            PHP,
        'header-shop.php' => <<<'PHP'
            <?php
            echo $acme_local;
            PHP,
    ];
}

it('passes $args to the template', function (): void {
    $result = scanTree(themeTree());

    expect(findingSignatures($result))->toContain('wp.xss.unescaped-output@2');
});

it('does not leak the caller locals into a template', function (): void {
    // The whole reason this is not modelled as an include. $acme_local is
    // tainted in index.php and echoed in header-shop.php, and there is no flow:
    // load_template() does not share the caller's scope.
    //
    // Getting this wrong would connect every variable in a theme's index.php to
    // every partial it renders — over-approximation in exactly the files a theme
    // puts its output in.
    $result = scanTree(themeTree());

    foreach ($result->findings->all() as $finding) {
        expect($finding->file)->not->toContain('header-shop.php');
    }
});

it('prefers the named variant, and falls back to the general template', function (): void {
    // `get_template_part( 'content', 'page' )` tries content-page.php first and
    // content.php after, which is the template hierarchy.
    $result = scanTree([
        'style.css' => "/* Theme Name: Acme */\n",
        'index.php' => <<<'PHP'
            <?php
            get_template_part('parts/content', 'page', array('v' => $_GET['v']));
            get_template_part('parts/other', 'missing', array('v' => $_GET['v']));
            PHP,
        'parts/content-page.php' => <<<'PHP'
            <?php
            echo $args['v'];
            PHP,
        'parts/other.php' => <<<'PHP'
            <?php
            echo $args['v'];
            PHP,
    ]);

    // The variant for the first call, the general template for the second,
    // whose named variant does not exist.
    $files = array_map(static fn (object $f): string => $f->file, $result->findings->all());

    expect($files)->toContain('parts/content-page.php');
    expect($files)->toContain('parts/other.php');
});

it('credits a template that escapes', function (): void {
    $result = scanTree([
        'style.css' => "/* Theme Name: Acme */\n",
        'index.php' => <<<'PHP'
            <?php
            get_template_part('parts/safe', null, array('v' => $_GET['v']));
            PHP,
        'parts/safe.php' => <<<'PHP'
            <?php
            echo esc_html($args['v']);
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
});

it('carries only the key that was tainted', function (): void {
    // Per-key array taint and template args together: $args['id'] is a literal
    // and reading it is not a finding, even though $args['title'] is tainted.
    $result = scanTree([
        'style.css' => "/* Theme Name: Acme */\n",
        'index.php' => <<<'PHP'
            <?php
            get_template_part('parts/card', null, array('title' => $_GET['title'], 'id' => 7));
            PHP,
        'parts/card.php' => <<<'PHP'
            <?php
            echo $args['id'];
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
});

it('records a slug it cannot resolve rather than guessing', function (): void {
    $result = scanTree([
        'style.css' => "/* Theme Name: Acme */\n",
        'index.php' => <<<'PHP'
            <?php
            function acme_render($slug) {
                get_template_part($slug, null, array('v' => $_GET['v']));
            }
            PHP,
    ]);

    expect($result->findings)->toBeEmpty();
    expect($result->unresolvedHooks)->not->toBeEmpty();
});

it('can be turned off with the includes', function (): void {
    $result = scanTree(themeTree(), new AnalysisOptions(followIncludes: false));

    expect($result->findings)->toBeEmpty();
});
