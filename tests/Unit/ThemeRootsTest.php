<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\ThemeRoots;

it('answers with the theme a file is inside', function (): void {
    $roots = ThemeRoots::fromFiles([
        '/site/wp-content/themes/acme-org/functions.php',
        '/site/wp-content/themes/acme-news/functions.php',
        '/site/wp-content/plugins/acme-shared/plugin.php',
    ]);

    expect($roots->forFile('/site/wp-content/themes/acme-org/includes/core.php'))
        ->toBe('/site/wp-content/themes/acme-org');
    expect($roots->forFile('/site/wp-content/themes/acme-news/single.php'))
        ->toBe('/site/wp-content/themes/acme-news');
});

it('answers a plugin file only when the scan holds exactly one theme', function (): void {
    $one = ThemeRoots::fromFiles([
        '/site/wp-content/themes/acme-org/functions.php',
        '/site/wp-content/plugins/acme-shared/plugin.php',
    ]);
    $two = ThemeRoots::fromFiles([
        '/site/wp-content/themes/acme-org/functions.php',
        '/site/wp-content/themes/acme-news/functions.php',
        '/site/wp-content/plugins/acme-shared/plugin.php',
    ]);

    // One theme: it must be the active one.
    expect($one->forFile('/site/wp-content/plugins/acme-shared/plugin.php'))
        ->toBe('/site/wp-content/themes/acme-org');

    // Two themes: genuinely ambiguous, so no answer rather than a guess.
    expect($two->forFile('/site/wp-content/plugins/acme-shared/plugin.php'))->toBeNull();
});

it('is empty when nothing in the scan lives under themes/', function (): void {
    $roots = ThemeRoots::fromFiles(['/site/wp-content/plugins/acme/plugin.php']);

    expect($roots->isEmpty())->toBeTrue();
    expect($roots->forFile('/site/wp-content/plugins/acme/plugin.php'))->toBeNull();
});
