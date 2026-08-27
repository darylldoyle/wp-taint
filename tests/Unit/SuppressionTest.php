<?php

declare(strict_types=1);

use Enshrined\WpTaint\Baseline\Baseline;
use Enshrined\WpTaint\Baseline\BaselineWriter;
use Enshrined\WpTaint\Baseline\InlineSuppressions;
use Enshrined\WpTaint\Finding\FindingCollection;

it('round-trips a baseline: generate, re-run, nothing reported', function (): void {
    $findings = FindingCollection::fromArray([
        makeFinding(fingerprint: 'aaa', line: 10),
        makeFinding(fingerprint: 'bbb', line: 20),
    ]);

    $path = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';

    try {
        expect((new BaselineWriter())->write($path, $findings))->toBe(2);

        $applied = Baseline::fromFile($path)->apply($findings);

        expect($applied['kept'])->toHaveCount(0);
        expect($applied['suppressed'])->toBe(2);
    } finally {
        @unlink($path);
    }
});

it('lets a new finding through an existing baseline', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';

    try {
        (new BaselineWriter())->write($path, FindingCollection::fromArray([makeFinding(fingerprint: 'old')]));

        $applied = Baseline::fromFile($path)->apply(FindingCollection::fromArray([
            makeFinding(fingerprint: 'old'),
            makeFinding(fingerprint: 'new', line: 40),
        ]));

        expect($applied['kept'])->toHaveCount(1);
        expect($applied['kept']->all()[0]->fingerprint)->toBe('new');
        expect($applied['suppressed'])->toBe(1);
    } finally {
        @unlink($path);
    }
});

it('writes a baseline that is readable, not just a list of hashes', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';

    try {
        (new BaselineWriter())->write($path, FindingCollection::fromArray([makeFinding()]));

        /** @var array{findings: list<array<string, string>>} $decoded */
        $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

        expect(array_keys($decoded['findings'][0]))
            ->toBe(['fingerprint', 'ruleId', 'severity', 'file', 'message']);
    } finally {
        @unlink($path);
    }
});

it('writes a byte-identical baseline for the same findings', function (): void {
    // No timestamps and no line numbers, so the file only changes when the
    // accepted set changes.
    $a = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';
    $b = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';

    try {
        $findings = FindingCollection::fromArray([
            makeFinding(fingerprint: 'x'),
            makeFinding(fingerprint: 'y', line: 2),
        ]);

        (new BaselineWriter())->write($a, $findings);
        (new BaselineWriter())->write($b, $findings);

        expect(file_get_contents($a))->toBe(file_get_contents($b));
    } finally {
        @unlink($a);
        @unlink($b);
    }
});

it('rejects a baseline file that is not valid JSON', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'wp-taint-baseline') . '.json';
    file_put_contents($path, '{not json');

    try {
        expect(static fn (): Baseline => Baseline::fromFile($path))
            ->toThrow(RuntimeException::class, 'not valid JSON');
    } finally {
        @unlink($path);
    }
});

it('suppresses the line after an inline ignore comment', function (): void {
    $suppressions = new InlineSuppressions();
    $suppressions->addFile('a.php', <<<'PHP'
        <?php
        // wp-taint-ignore-next-line wp.xss.unescaped-output -- reviewed, output is admin-only
        echo $x;
        PHP);

    // The comment is on line 2, so the finding it suppresses is on line 3.
    expect($suppressions->suppresses(makeFinding(line: 3)))->toBeTrue();
    expect($suppressions->suppresses(makeFinding(line: 2)))->toBeFalse();
});

it('demands a reason and reports a suppression without one', function (): void {
    $suppressions = new InlineSuppressions();
    $suppressions->addFile('a.php', <<<'PHP'
        <?php
        // wp-taint-ignore-next-line wp.xss.unescaped-output
        echo $x;
        PHP);

    expect($suppressions->suppresses(makeFinding(line: 3)))->toBeFalse();
    expect($suppressions->malformed())->toHaveCount(1);
    expect($suppressions->malformed()[0]->reason)->toContain('no reason given');
});

it('only suppresses the named rule', function (): void {
    $suppressions = new InlineSuppressions();
    $suppressions->addFile('a.php', <<<'PHP'
        <?php
        // wp-taint-ignore-next-line wp.sqli.wpdb-query -- prepared upstream
        echo $x;
        PHP);

    expect($suppressions->suppresses(makeFinding(ruleId: 'wp.xss.unescaped-output', line: 3)))->toBeFalse();
    expect($suppressions->suppresses(makeFinding(ruleId: 'wp.sqli.wpdb-query', line: 3)))->toBeTrue();
});

it('supports a rule family wildcard', function (): void {
    $suppressions = new InlineSuppressions();
    $suppressions->addFile('a.php', <<<'PHP'
        <?php
        // wp-taint-ignore-next-line wp.xss.* -- template is escaped by the caller
        echo $x;
        PHP);

    expect($suppressions->suppresses(makeFinding(ruleId: 'wp.xss.unescaped-output', line: 3)))->toBeTrue();
    expect($suppressions->suppresses(makeFinding(ruleId: 'wp.sqli.wpdb-query', line: 3)))->toBeFalse();
});

it('counts what it suppressed so the debt stays visible', function (): void {
    $suppressions = new InlineSuppressions();
    $suppressions->addFile('a.php', <<<'PHP'
        <?php
        // wp-taint-ignore-next-line wp.xss.unescaped-output -- known safe
        echo $x;
        PHP);

    $applied = $suppressions->apply(FindingCollection::fromArray([makeFinding(line: 3)]));

    expect($applied['kept'])->toHaveCount(0);
    expect($applied['suppressed'])->toBe(1);
});
