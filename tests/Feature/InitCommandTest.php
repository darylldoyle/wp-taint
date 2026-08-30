<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cli\Command\InitCommand;
use Symfony\Component\Console\Tester\CommandTester;

function initInto(array $dirs): string
{
    $root = sys_get_temp_dir() . '/wp-taint-init-' . bin2hex(random_bytes(6));

    foreach ($dirs as $dir) {
        mkdir($root . '/' . $dir, 0o755, true);
    }

    return $root;
}

it('writes a commented template when it cannot ask', function (): void {
    $root = initInto([
        'wp-content/themes/acme-theme',
        'wp-content/plugins/acme-plugin',
    ]);

    $tester = new CommandTester(new InitCommand());
    $tester->execute(['root' => $root . '/wp-content'], ['interactive' => false]);

    $config = file_get_contents($root . '/wp-content/wp-taint.toml');

    expect($tester->getStatusCode())->toBe(0);
    // Every candidate present, commented out for the developer to choose.
    expect($config)->toContain('# "themes/acme-theme",');
    expect($config)->toContain('# "plugins/acme-plugin",');
    expect($config)->toContain('[scan.options]');

    exec('rm -rf ' . escapeshellarg($root));
});

it('writes every directory under --all', function (): void {
    $root = initInto([
        'wp-content/themes/acme-theme',
        'wp-content/plugins/acme-plugin',
    ]);

    $tester = new CommandTester(new InitCommand());
    $tester->execute(['root' => $root . '/wp-content', '--all' => true], ['interactive' => false]);

    $config = file_get_contents($root . '/wp-content/wp-taint.toml');

    expect($config)->toContain('"themes/acme-theme"');
    expect($config)->toContain('"plugins/acme-plugin"');
    expect($config)->not->toContain('# "themes/acme-theme"');

    exec('rm -rf ' . escapeshellarg($root));
});

it('refuses to overwrite without --force', function (): void {
    $root = initInto(['wp-content/themes/acme-theme']);
    file_put_contents($root . '/wp-content/wp-taint.toml', 'existing');

    $tester = new CommandTester(new InitCommand());
    $tester->execute(['root' => $root . '/wp-content'], ['interactive' => false]);

    expect($tester->getStatusCode())->toBe(2);
    expect(file_get_contents($root . '/wp-content/wp-taint.toml'))->toBe('existing');

    exec('rm -rf ' . escapeshellarg($root));
});

it('errors when the root is not a WordPress tree', function (): void {
    $root = initInto(['src']);

    $tester = new CommandTester(new InitCommand());
    $tester->execute(['root' => $root], ['interactive' => false]);

    expect($tester->getStatusCode())->toBe(2);

    exec('rm -rf ' . escapeshellarg($root));
});
