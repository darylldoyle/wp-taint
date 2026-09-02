<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cli\Command\InitCommand;
use Laravel\Prompts\Key;
use Laravel\Prompts\Prompt;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The real command only prompts on a real terminal, which a test does not have.
 * The constructor seam forces the interactive branch so the multiselect can be
 * driven with {@see Prompt::fake()}; nothing else changes.
 */
function promptingInit(): InitCommand
{
    return new InitCommand(promptGate: static fn (): bool => true);
}

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

it('writes the checked directory to paths and the rest to reference', function (): void {
    $root = initInto([
        'wp-content/themes/acme-theme',
        'wp-content/plugins/acme-plugin',
        'wp-content/plugins/vendor-plugin',
    ]);

    // Space checks the first option (themes/acme-theme), Enter confirms.
    Prompt::fake([Key::SPACE, Key::ENTER]);

    $tester = new CommandTester(promptingInit());
    $tester->execute(['root' => $root . '/wp-content']);

    $config = file_get_contents($root . '/wp-content/wp-taint.toml');

    expect($tester->getStatusCode())->toBe(0);
    expect($config)->toContain('paths = ["themes/acme-theme"]');
    // The two unchecked directories become reference-only, not scanned.
    expect($config)->toContain('reference = ["plugins/acme-plugin", "plugins/vendor-plugin"]');

    exec('rm -rf ' . escapeshellarg($root));
});

it('writes nothing when the interactive selection is empty', function (): void {
    $root = initInto(['wp-content/themes/acme-theme']);

    // Enter with nothing checked.
    Prompt::fake([Key::ENTER]);

    $tester = new CommandTester(promptingInit());
    $tester->execute(['root' => $root . '/wp-content']);

    expect($tester->getStatusCode())->toBe(0);
    expect(is_file($root . '/wp-content/wp-taint.toml'))->toBeFalse();

    exec('rm -rf ' . escapeshellarg($root));
});
