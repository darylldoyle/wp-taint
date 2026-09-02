<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cli\Application;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @param array<string, mixed> $options
 *
 * @return list<array{line: int, severity: string, acknowledged: ?array{sniff: string, reason: ?string}}>
 */
function scanForAck(string $php, array $options = []): array
{
    $file = sys_get_temp_dir() . '/wp-taint-ack-' . bin2hex(random_bytes(6)) . '.php';
    file_put_contents($file, $php);

    try {
        // Through the Application so the global options the command reads
        // (--no-ansi and the rest) are defined.
        $tester = new CommandTester((new Application())->find('scan'));
        $tester->execute([
            'paths' => [$file],
            '--format' => 'json',
            '--min-severity' => 'notice',
            '--fail-on' => 'never',
            ...$options,
        ], ['interactive' => false]);

        $json = json_decode($tester->getDisplay(), true, 512, JSON_THROW_ON_ERROR);

        return array_map(static fn (array $f): array => [
            'line' => $f['location']['line'],
            'severity' => $f['severity'],
            'acknowledged' => $f['acknowledged'] ?? null,
        ], $json['findings']);
    } finally {
        @unlink($file);
    }
}

/**
 * The same scan rendered for a human, so the console wording can be asserted.
 */
function scanForAckConsole(string $php): string
{
    $file = sys_get_temp_dir() . '/wp-taint-ack-' . bin2hex(random_bytes(6)) . '.php';
    file_put_contents($file, $php);

    try {
        $tester = new CommandTester((new Application())->find('scan'));
        $tester->execute([
            'paths' => [$file],
            '--min-severity' => 'notice',
            '--fail-on' => 'never',
            '--no-ansi' => true,
        ], ['interactive' => false]);

        return $tester->getDisplay();
    } finally {
        @unlink($file);
    }
}

it('downgrades a finding whose line names the matching sniff', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- from a block
        }
        PHP);

    expect($findings)->toHaveCount(1);
    expect($findings[0]['severity'])->toBe('notice');
    expect($findings[0]['acknowledged']['sniff'])->toBe('WordPress.Security.EscapeOutput.OutputNotEscaped');
    expect($findings[0]['acknowledged']['reason'])->toBe('from a block');
});

it('leaves a finding with no ignore at full severity', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x'];
        }
        PHP);

    expect($findings[0]['severity'])->toBe('high');
    expect($findings[0]['acknowledged'])->toBeNull();
});

it('does not downgrade for an unrelated sniff', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment -- not about escaping
        }
        PHP);

    expect($findings[0]['severity'])->toBe('high');
});

it('does not downgrade for a bare ignore with no sniff named', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore -- silences everything, says nothing about escaping
        }
        PHP);

    expect($findings[0]['severity'])->toBe('high');
});

it('does not honour a phpcs:disable block', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            // phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
            echo $_GET['x'];
            // phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
        }
        PHP);

    expect($findings[0]['severity'])->toBe('high');
});

it('honours a standalone ignore on the line above', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- reviewed
            echo $_GET['x'];
        }
        PHP);

    expect($findings[0]['severity'])->toBe('notice');
});

it('keeps the severity it was reduced from in the data model', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- reviewed
        }
        PHP);

    expect($findings[0]['severity'])->toBe('notice');
    expect($findings[0]['acknowledged']['reducedFrom'])->toBe('high');
});

it('names the sniff and what the severity was reduced from in the console', function (): void {
    $display = scanForAckConsole(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- reviewed
        }
        PHP);

    expect($display)->toContain(
        'Acknowledged in PHPCS with WordPress.Security.EscapeOutput.OutputNotEscaped; '
            . 'severity reduced from high to notice.',
    );
    expect($display)->not->toContain('reporting as a notice rather than a finding');
});

it('reports at full severity under --no-phpcs-suppressions', function (): void {
    $findings = scanForAck(<<<'PHP'
        <?php
        function acme() {
            echo $_GET['x']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- reviewed
        }
        PHP, ['--no-phpcs-suppressions' => true]);

    expect($findings[0]['severity'])->toBe('high');
    expect($findings[0]['acknowledged'])->toBeNull();
});
