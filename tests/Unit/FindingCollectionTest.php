<?php

declare(strict_types=1);

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\FindingCollection;
use Enshrined\WpTaint\Finding\RuleDefinition;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

function makeFinding(
    string $ruleId = 'wp.xss.unescaped-output',
    string $file = 'a.php',
    int $line = 10,
    int $column = 1,
    Severity $severity = Severity::High,
    TaintKind $kind = TaintKind::Html,
    string $fingerprint = 'abc123',
): Finding {
    $step = new TraceStep(
        TraceVerb::Sink,
        $file,
        $line,
        $column,
        null,
        'echo $x;',
        'Reaches echo.',
        TaintSet::of($kind),
    );

    return new Finding(
        $ruleId,
        new RuleDefinition($ruleId, 'Title', 'Description', 'Remediation'),
        $severity,
        $kind,
        $file,
        $line,
        $column,
        null,
        'message',
        [$step],
        $fingerprint,
    );
}

it('sorts by file, then line, then column, then rule id', function (): void {
    $collection = FindingCollection::fromArray([
        makeFinding(file: 'b.php', line: 1, fingerprint: '1'),
        makeFinding(file: 'a.php', line: 20, fingerprint: '2'),
        makeFinding(file: 'a.php', line: 5, column: 9, fingerprint: '3'),
        makeFinding(file: 'a.php', line: 5, column: 2, fingerprint: '4'),
        makeFinding(ruleId: 'wp.sqli.wpdb-query', file: 'a.php', line: 5, column: 2, fingerprint: '5'),
    ]);

    $signatures = array_map(
        static fn (Finding $f): string => sprintf('%s:%d:%d:%s', $f->file, $f->line, $f->column, $f->ruleId),
        $collection->all(),
    );

    expect($signatures)->toBe([
        'a.php:5:2:wp.sqli.wpdb-query',
        'a.php:5:2:wp.xss.unescaped-output',
        'a.php:5:9:wp.xss.unescaped-output',
        'a.php:20:1:wp.xss.unescaped-output',
        'b.php:1:1:wp.xss.unescaped-output',
    ]);
});

it('de-duplicates identical findings from different passes', function (): void {
    $collection = FindingCollection::fromArray([
        makeFinding(),
        makeFinding(),
        makeFinding(),
    ]);

    expect($collection)->toHaveCount(1);
});

it('produces byte-identical ordering regardless of input order', function (): void {
    $findings = [
        makeFinding(file: 'z.php', line: 3, fingerprint: 'a'),
        makeFinding(file: 'a.php', line: 90, fingerprint: 'b'),
        makeFinding(file: 'm.php', line: 1, fingerprint: 'c'),
    ];

    $forward = FindingCollection::fromArray($findings);
    $reversed = FindingCollection::fromArray(array_reverse($findings));

    $signature = static fn (FindingCollection $c): array => array_map(
        static fn (Finding $f): string => $f->fingerprint,
        $c->all(),
    );

    expect($signature($forward))->toBe($signature($reversed));
});

it('filters by minimum severity', function (): void {
    $collection = FindingCollection::fromArray([
        makeFinding(severity: Severity::Low, fingerprint: '1'),
        makeFinding(severity: Severity::High, line: 11, fingerprint: '2'),
        makeFinding(severity: Severity::Critical, line: 12, fingerprint: '3'),
    ]);

    expect($collection->withMinimumSeverity(Severity::High))->toHaveCount(2);
    expect($collection->withMinimumSeverity(Severity::Critical))->toHaveCount(1);
    expect($collection->withMinimumSeverity(Severity::Low))->toHaveCount(3);
});

it('reports whether anything reaches the fail-on threshold', function (): void {
    $collection = FindingCollection::fromArray([makeFinding(severity: Severity::Medium)]);

    expect($collection->hasAtLeast(Severity::Medium))->toBeTrue();
    expect($collection->hasAtLeast(Severity::High))->toBeFalse();
});

it('drops a shape finding when a taint finding covers the same place', function (): void {
    // The shape rule exists to catch what dataflow cannot reach. When dataflow
    // did reach it, reporting both is noise.
    $collection = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.sqli.unprepared-query', kind: TaintKind::Sql, fingerprint: '1'),
        makeFinding(ruleId: 'wp.sqli.wpdb-query', kind: TaintKind::Sql, fingerprint: '2'),
    ])->withRulePrecedence(['wp.sqli.unprepared-query' => []]);

    expect($collection)->toHaveCount(1);
    expect($collection->all()[0]->ruleId)->toBe('wp.sqli.wpdb-query');
});

it('keeps a shape finding when nothing else covers it', function (): void {
    $collection = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.sqli.unprepared-query', kind: TaintKind::Sql, fingerprint: '1'),
    ])->withRulePrecedence(['wp.sqli.unprepared-query' => []]);

    expect($collection)->toHaveCount(1);
});

it('applies a named precedence only against the named rule', function (): void {
    $precedence = ['wp.sqli.wpdb-query' => ['wp.sqli.prepare-non-literal']];

    $both = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.sqli.wpdb-query', kind: TaintKind::Sql, fingerprint: '1'),
        makeFinding(ruleId: 'wp.sqli.prepare-non-literal', kind: TaintKind::Sql, fingerprint: '2'),
    ])->withRulePrecedence($precedence);

    expect($both->all()[0]->ruleId)->toBe('wp.sqli.prepare-non-literal');

    $unrelated = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.sqli.wpdb-query', kind: TaintKind::Sql, fingerprint: '1'),
        makeFinding(ruleId: 'wp.xss.unescaped-output', kind: TaintKind::Sql, fingerprint: '2'),
    ])->withRulePrecedence($precedence);

    expect($unrelated)->toHaveCount(2);
});

it('counts by severity with every bucket present', function (): void {
    $counts = FindingCollection::fromArray([makeFinding(severity: Severity::High)])->countsBySeverity();

    expect(array_keys($counts))->toBe(['critical', 'high', 'medium', 'low', 'notice']);
    expect($counts['high'])->toBe(1);
    expect($counts['low'])->toBe(0);
    expect($counts['notice'])->toBe(0);
});

it('groups by file in sorted order', function (): void {
    $grouped = FindingCollection::fromArray([
        makeFinding(file: 'z.php', fingerprint: '1'),
        makeFinding(file: 'a.php', fingerprint: '2'),
    ])->groupedByFile();

    expect(array_keys($grouped))->toBe(['a.php', 'z.php']);
});
