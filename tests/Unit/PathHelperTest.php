<?php

declare(strict_types=1);

use Enshrined\WpTaint\Support\PathHelper;

it('makes paths relative to the scan root', function (): void {
    expect(PathHelper::relative('/a/b/c/file.php', '/a/b'))->toBe('c/file.php');
    expect(PathHelper::relative('/a/b/c/file.php', '/a/b/'))->toBe('c/file.php');
});

it('leaves a path outside the root alone', function (): void {
    expect(PathHelper::relative('/x/y/file.php', '/a/b'))->toBe('/x/y/file.php');
});

it('finds the common root of several paths', function (): void {
    $root = PathHelper::commonRoot([
        projectRoot() . '/src/Taint',
        projectRoot() . '/src/Registry',
    ]);

    expect($root)->toBe(PathHelper::normalise(projectRoot() . '/src'));
});

it('uses the containing directory when given files', function (): void {
    $root = PathHelper::commonRoot([projectRoot() . '/composer.json']);

    expect($root)->toBe(PathHelper::normalise(projectRoot()));
});
