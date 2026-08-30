<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cli\ProjectLayout;

/**
 * @param list<string> $dirs directories to create, relative to a fresh root
 */
function layoutOf(array $dirs, string $from = ''): ProjectLayout
{
    $root = sys_get_temp_dir() . '/wp-taint-layout-' . bin2hex(random_bytes(6));

    foreach ($dirs as $dir) {
        mkdir($root . '/' . $dir, 0o755, true);
    }

    try {
        return ProjectLayout::discover($from === '' ? $root : $root . '/' . $from);
    } finally {
        exec('rm -rf ' . escapeshellarg($root));
    }
}

it('lists themes, plugins and mu-plugins under a wp-content directory', function (): void {
    $layout = layoutOf([
        'wp-content/themes/acme-theme',
        'wp-content/plugins/acme-plugin',
        'wp-content/mu-plugins/acme-mu',
        'wp-content/client-mu-plugins/acme-client',
    ], 'wp-content');

    expect($layout->themes)->toBe(['themes/acme-theme']);
    expect($layout->plugins)->toBe(['plugins/acme-plugin']);
    expect($layout->muPlugins)->toContain('mu-plugins/acme-mu', 'client-mu-plugins/acme-client');
});

it('finds wp-content from a project root above it', function (): void {
    $layout = layoutOf([
        'wp-content/themes/acme-theme',
        'wp-content/plugins/acme-plugin',
    ]);

    expect($layout->all())->toContain('themes/acme-theme', 'plugins/acme-plugin');
});

it('never lists vendor or build directories as candidates', function (): void {
    $layout = layoutOf([
        'wp-content/plugins/acme-plugin',
        'wp-content/plugins/vendor',
        'wp-content/plugins/node_modules',
    ], 'wp-content');

    expect($layout->plugins)->toBe(['plugins/acme-plugin']);
});

it('is empty when the root is not a WordPress tree', function (): void {
    $layout = layoutOf(['src', 'docs']);

    expect($layout->isEmpty())->toBeTrue();
});
