<?php

declare(strict_types=1);

use Enshrined\WpTaint\Finding\Acknowledgement;
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

it('collapses the unescaped-output family to the most specific finding at a line', function (): void {
    // The real precedence from Scanner: escape-voided ⊐ unescaped-output ⊐
    // unescaped-unknown. Three findings at one line, three different kinds,
    // one story about the same echo. Only the most specific survives.
    $precedence = [
        'wp.output.unescaped-unknown' => ['wp.xss.unescaped-output', 'wp.xss.escape-voided'],
        'wp.xss.unescaped-output' => ['wp.xss.escape-voided'],
    ];

    $all = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.output.unescaped-unknown', kind: TaintKind::Unknown, fingerprint: '1'),
        makeFinding(ruleId: 'wp.xss.unescaped-output', kind: TaintKind::Html, fingerprint: '2'),
        makeFinding(ruleId: 'wp.xss.escape-voided', kind: TaintKind::EscapeVoided, fingerprint: '3'),
    ])->withRulePrecedence($precedence);

    expect($all->all())->toHaveCount(1);
    expect($all->all()[0]->ruleId)->toBe('wp.xss.escape-voided');

    // With no escape-voided, unescaped-output is the most specific and wins.
    $withoutVoided = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.output.unescaped-unknown', kind: TaintKind::Unknown, fingerprint: '1'),
        makeFinding(ruleId: 'wp.xss.unescaped-output', kind: TaintKind::Html, fingerprint: '2'),
    ])->withRulePrecedence($precedence);

    expect($withoutVoided->all())->toHaveCount(1);
    expect($withoutVoided->all()[0]->ruleId)->toBe('wp.xss.unescaped-output');
});

it('does not collapse the output family across different lines', function (): void {
    $precedence = ['wp.output.unescaped-unknown' => ['wp.xss.unescaped-output', 'wp.xss.escape-voided']];

    $collection = FindingCollection::fromArray([
        makeFinding(ruleId: 'wp.output.unescaped-unknown', kind: TaintKind::Unknown, line: 10, fingerprint: '1'),
        makeFinding(ruleId: 'wp.xss.unescaped-output', kind: TaintKind::Html, line: 20, fingerprint: '2'),
    ])->withRulePrecedence($precedence);

    expect($collection)->toHaveCount(2);
});

it('counts by severity with every bucket present', function (): void {
    $counts = FindingCollection::fromArray([makeFinding(severity: Severity::High)])->countsBySeverity();

    expect(array_keys($counts))->toBe(['critical', 'high', 'medium', 'low', 'notice']);
    expect($counts['high'])->toBe(1);
    expect($counts['low'])->toBe(0);
    expect($counts['notice'])->toBe(0);
});

it('orders by severity, most severe first, then canonically', function (): void {
    $ordered = FindingCollection::fromArray([
        makeFinding(severity: Severity::Notice, file: 'a.php', fingerprint: '1'),
        makeFinding(severity: Severity::Critical, file: 'z.php', fingerprint: '2'),
        makeFinding(severity: Severity::High, file: 'm.php', fingerprint: '3'),
        makeFinding(severity: Severity::High, file: 'b.php', fingerprint: '4'),
    ])->orderedBySeverity();

    expect(array_map(static fn ($f): string => $f->severity->value, $ordered))
        ->toBe(['critical', 'high', 'high', 'notice']);
    // Within the two highs, canonical file order holds: b.php before m.php.
    expect($ordered[1]->file)->toBe('b.php');
    expect($ordered[2]->file)->toBe('m.php');
});

it('orders notices by the severity they were reduced from, then canonically', function (): void {
    $ack = new Acknowledgement('Std.Cat.Sniff');

    // Deliberately shuffled input, mixed original severities and files.
    $ordered = FindingCollection::fromArray([
        makeFinding(severity: Severity::Low, file: 'a.php', fingerprint: '1')->acknowledged($ack),
        makeFinding(severity: Severity::Critical, file: 'z.php', fingerprint: '2')->acknowledged($ack),
        makeFinding(severity: Severity::High, file: 'm.php', fingerprint: '3')->acknowledged($ack),
        makeFinding(severity: Severity::Critical, file: 'b.php', fingerprint: '4')->acknowledged($ack),
    ])->orderedBySeverity();

    // Every finding is effectively a notice, so ordering is by original severity
    // descending, then canonical file order within a tie.
    expect(array_map(static fn ($f): string => $f->severity->value, $ordered))
        ->toBe(['notice', 'notice', 'notice', 'notice']);
    expect(array_map(
        static fn ($f): string => $f->acknowledgement->originalSeverity->value . ':' . $f->file,
        $ordered,
    ))->toBe(['critical:b.php', 'critical:z.php', 'high:m.php', 'low:a.php']);
});

it('ranks an acknowledged higher-severity notice above a plain lower notice deterministically', function (): void {
    $ack = new Acknowledgement('Std.Cat.Sniff');

    $ordered = FindingCollection::fromArray([
        // A genuine notice (never acknowledged): original severity is Notice.
        makeFinding(severity: Severity::Notice, file: 'a.php', fingerprint: '1'),
        // A critical acknowledged down to a notice.
        makeFinding(severity: Severity::Critical, file: 'z.php', fingerprint: '2')->acknowledged($ack),
    ])->orderedBySeverity();

    expect($ordered[0]->file)->toBe('z.php'); // reduced-from critical wins
    expect($ordered[1]->file)->toBe('a.php');
});

it('groups by file in sorted order', function (): void {
    $grouped = FindingCollection::fromArray([
        makeFinding(file: 'z.php', fingerprint: '1'),
        makeFinding(file: 'a.php', fingerprint: '2'),
    ])->groupedByFile();

    expect(array_keys($grouped))->toBe(['a.php', 'z.php']);
});
