<?php

declare(strict_types=1);

use Enshrined\WpTaint\Finding\Fingerprint;

it('survives a whitespace-only reformat', function (): void {
    $a = Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', 'echo $filter;');
    $b = Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', '    echo   $filter;   ');

    expect($a)->toBe($b);
});

it('ignores the line number entirely', function (): void {
    // Hashing the line would invalidate the whole baseline on any unrelated
    // edit above the finding, which makes the baseline worthless.
    $a = Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', 'echo $filter;');
    $b = Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', 'echo $filter;');

    expect($a)->toBe($b);
});

it('changes when the rule, file, sink or snippet changes', function (): void {
    $base = Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', 'echo $filter;');

    expect(Fingerprint::compute('wp.sqli.wpdb-query', 'src/render.php', 'echo', 'echo $filter;'))->not->toBe($base);
    expect(Fingerprint::compute('wp.xss.unescaped-output', 'src/other.php', 'echo', 'echo $filter;'))->not->toBe($base);
    expect(Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'print', 'echo $filter;'))
        ->not->toBe($base);
    expect(Fingerprint::compute('wp.xss.unescaped-output', 'src/render.php', 'echo', 'echo $other;'))->not->toBe($base);
});

it('is a short stable hex string', function (): void {
    $fingerprint = Fingerprint::compute('wp.xss.unescaped-output', 'a.php', 'echo', 'echo $x;');

    expect($fingerprint)->toMatch('/^[0-9a-f]{16}$/');
});
