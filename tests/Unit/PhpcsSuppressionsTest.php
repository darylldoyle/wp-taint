<?php

declare(strict_types=1);

use Enshrined\WpTaint\Baseline\PhpcsSuppressions;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\RuleDefinition;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Taint\TaintKind;

function findingAt(int $line, string $file = 'x.php'): Finding
{
    return new Finding(
        'wp.xss.unescaped-output',
        new RuleDefinition('wp.xss.unescaped-output', 't', 'd', 'r'),
        Severity::High,
        TaintKind::Html,
        $file,
        $line,
        1,
        null,
        'm',
        [],
        'fp',
    );
}

/** @param list<string> $lines */
function phpcsFor(array $lines): PhpcsSuppressions
{
    $s = new PhpcsSuppressions();
    $s->addFile('x.php', "<?php\n" . implode("\n", $lines) . "\n");

    return $s;
}

$escape = ['WordPress.Security.EscapeOutput.OutputNotEscaped'];

it('acknowledges a trailing ignore naming the matching sniff', function () use ($escape): void {
    // Line 2 in the file (after the <?php on line 1).
    $s = phpcsFor(['echo $x; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- reviewed']);

    $ack = $s->acknowledgementFor(findingAt(2), $escape);

    expect($ack)->not->toBeNull();
    expect($ack->sniff)->toBe('WordPress.Security.EscapeOutput.OutputNotEscaped');
    expect($ack->reason)->toBe('reviewed');
});

it('acknowledges a standalone ignore for the line below it', function () use ($escape): void {
    $s = phpcsFor([
        '// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped',
        'echo $x;',
    ]);

    expect($s->acknowledgementFor(findingAt(2), $escape))->toBeNull(); // the comment line
    expect($s->acknowledgementFor(findingAt(3), $escape))->not->toBeNull(); // the code below
});

it('accepts the sniff category as covering its error code', function () use ($escape): void {
    $s = phpcsFor(['echo $x; // phpcs:ignore WordPress.Security.EscapeOutput -- category form']);

    expect($s->acknowledgementFor(findingAt(2), $escape))->not->toBeNull();
});

it('rejects a bare ignore with no sniff', function () use ($escape): void {
    $s = phpcsFor(['echo $x; // phpcs:ignore -- nothing named']);

    expect($s->acknowledgementFor(findingAt(2), $escape))->toBeNull();
});

it('rejects a sniff too broad to be a line review', function () use ($escape): void {
    // Two segments only: a whole category, not a specific sniff.
    $s = phpcsFor(['echo $x; // phpcs:ignore WordPress.Security -- too broad']);

    expect($s->acknowledgementFor(findingAt(2), $escape))->toBeNull();
});

it('rejects an unrelated sniff', function () use ($escape): void {
    $s = phpcsFor(['echo $x; // phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment']);

    expect($s->acknowledgementFor(findingAt(2), $escape))->toBeNull();
});

it('never reads phpcs:disable', function () use ($escape): void {
    $s = phpcsFor([
        '// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped',
        'echo $x;',
        '// phpcs:enable',
    ]);

    expect($s->acknowledgementFor(findingAt(3), $escape))->toBeNull();
});

it('acknowledges one of several sniffs listed together', function () use ($escape): void {
    $s = phpcsFor([
        'echo $x; // phpcs:ignore WordPress.WP.I18n.MissingTranslatorsComment, '
            . 'WordPress.Security.EscapeOutput.OutputNotEscaped',
    ]);

    expect($s->acknowledgementFor(findingAt(2), $escape))->not->toBeNull();
});

it('returns null when the rule maps to no sniffs', function (): void {
    $s = phpcsFor(['echo $x; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped']);

    expect($s->acknowledgementFor(findingAt(2), []))->toBeNull();
});
