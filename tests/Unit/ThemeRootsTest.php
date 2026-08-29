<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\ThemeRoots;

it('answers with the theme a file is inside', function (): void {
    $roots = ThemeRoots::fromFiles([
        '/site/wp-content/themes/acme-org/functions.php',
        '/site/wp-content/themes/acme-news/functions.php',
        '/site/wp-content/plugins/acme-shared/plugin.php',
    ]);

    expect($roots->stylesheetRootsFor('/site/wp-content/themes/acme-org/includes/core.php'))
        ->toBe(['/site/wp-content/themes/acme-org']);
    expect($roots->stylesheetRootsFor('/site/wp-content/themes/acme-news/single.php'))
        ->toBe(['/site/wp-content/themes/acme-news']);
});

it('answers a plugin file with every candidate theme', function (): void {
    $roots = ThemeRoots::fromFiles([
        '/site/wp-content/themes/acme-org/functions.php',
        '/site/wp-content/themes/acme-news/functions.php',
        '/site/wp-content/plugins/acme-shared/plugin.php',
    ]);

    // A plugin runs under whichever theme is active, and any scanned theme
    // could be it: the union, the same answer a two-valued hook name gets.
    expect($roots->stylesheetRootsFor('/site/wp-content/plugins/acme-shared/plugin.php'))
        ->toBe(['/site/wp-content/themes/acme-org', '/site/wp-content/themes/acme-news']);
});

it('reads a child theme parent from style.css the way WordPress does', function (): void {
    $base = sys_get_temp_dir() . '/wp-taint-themeroots-' . uniqid();
    mkdir($base . '/themes/acme-parent', 0777, true);
    mkdir($base . '/themes/acme-child', 0777, true);
    file_put_contents($base . '/themes/acme-parent/style.css', "/*\nTheme Name: Parent\n*/");
    file_put_contents(
        $base . '/themes/acme-child/style.css',
        "/*\nTheme Name: Child\nTemplate: acme-parent\n*/",
    );

    $roots = ThemeRoots::fromFiles([
        $base . '/themes/acme-parent/functions.php',
        $base . '/themes/acme-child/functions.php',
    ]);

    // The child's stylesheet dir is itself; its template dir is the parent.
    expect($roots->stylesheetRootsFor($base . '/themes/acme-child/single.php'))
        ->toBe([$base . '/themes/acme-child']);
    expect($roots->templateRootsFor($base . '/themes/acme-child/single.php'))
        ->toBe([$base . '/themes/acme-parent']);

    // The parent declares no Template, so it is its own template root.
    expect($roots->templateRootsFor($base . '/themes/acme-parent/single.php'))
        ->toBe([$base . '/themes/acme-parent']);

    // Template-hierarchy lookup falls back from child to parent.
    expect($roots->parentsOf($base . '/themes/acme-child'))
        ->toBe([$base . '/themes/acme-parent']);

    // get_theme_file_path(): the child's copy when the scan has it, the
    // parent's otherwise — WordPress's override order.
    $roots2 = ThemeRoots::fromFiles([
        $base . '/themes/acme-parent/functions.php',
        $base . '/themes/acme-parent/partials/card.php',
        $base . '/themes/acme-child/functions.php',
        $base . '/themes/acme-child/partials/hero.php',
    ]);
    expect($roots2->themeFilePathsFor($base . '/themes/acme-child/single.php', 'partials/hero.php'))
        ->toBe([$base . '/themes/acme-child/partials/hero.php']);
    expect($roots2->themeFilePathsFor($base . '/themes/acme-child/single.php', 'partials/card.php'))
        ->toBe([$base . '/themes/acme-parent/partials/card.php']);

    array_map('unlink', glob($base . '/themes/*/style.css'));
    rmdir($base . '/themes/acme-parent');
    rmdir($base . '/themes/acme-child');
    rmdir($base . '/themes');
    rmdir($base);
});

it('folds a child to nothing when its declared parent is not in the scan', function (): void {
    $base = sys_get_temp_dir() . '/wp-taint-themeroots-' . uniqid();
    mkdir($base . '/themes/acme-child', 0777, true);
    file_put_contents(
        $base . '/themes/acme-child/style.css',
        "/*\nTheme Name: Child\nTemplate: acme-parent\n*/",
    );

    $roots = ThemeRoots::fromFiles([$base . '/themes/acme-child/functions.php']);

    // Every path built on the true answer names files the scan does not hold,
    // and folding to the child instead would be wrong in a way that looks
    // resolved.
    expect($roots->templateRootsFor($base . '/themes/acme-child/single.php'))->toBe([]);

    unlink($base . '/themes/acme-child/style.css');
    rmdir($base . '/themes/acme-child');
    rmdir($base . '/themes');
    rmdir($base);
});

it('is empty when nothing in the scan lives under themes/', function (): void {
    $roots = ThemeRoots::fromFiles(['/site/wp-content/plugins/acme/plugin.php']);

    expect($roots->isEmpty())->toBeTrue();
});
