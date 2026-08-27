<?php

declare(strict_types=1);

use Enshrined\WpTaint\Finding\Severity;

it('orders severities', function (): void {
    expect(Severity::Critical->atLeast(Severity::High))->toBeTrue();
    expect(Severity::Low->atLeast(Severity::Medium))->toBeFalse();
    expect(Severity::High->atLeast(Severity::High))->toBeTrue();
});

it('maps to SARIF levels, which have no critical', function (): void {
    expect(Severity::Critical->sarifLevel())->toBe('error');
    expect(Severity::High->sarifLevel())->toBe('error');
    expect(Severity::Medium->sarifLevel())->toBe('warning');
    expect(Severity::Low->sarifLevel())->toBe('note');
});

it('carries a numeric security severity for viewer sort order', function (): void {
    $values = array_map(
        static fn (Severity $s): float => (float) $s->securitySeverity(),
        [Severity::Low, Severity::Medium, Severity::High, Severity::Critical],
    );

    expect($values)->toBe([3.0, 5.0, 7.0, 9.0]);
});

it('rejects unknown severities by name', function (): void {
    expect(static fn (): Severity => Severity::fromString('catastrophic'))
        ->toThrow(InvalidArgumentException::class);
});
