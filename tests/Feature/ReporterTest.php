<?php

declare(strict_types=1);

use Enshrined\WpTaint\Report\Ansi;
use Enshrined\WpTaint\Report\ConsoleReporter;
use Enshrined\WpTaint\Report\JsonReporter;
use Enshrined\WpTaint\Report\ReportOptions;
use Enshrined\WpTaint\Report\SarifReporter;

function reportableScan(): Enshrined\WpTaint\Scan\ScanResult
{
    return scanFixture('vulnerable/xss-two-hop.php');
}

it('emits self-describing JSON with the rule definition inline', function (): void {
    // An agent reading findings.json cold should need no lookup table.
    $payload = json_decode(
        (new JsonReporter())->render(reportableScan(), new ReportOptions()),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    expect($payload['schemaVersion'])->toBe('1.0');
    expect($payload['tool']['name'])->toBe('wp-taint');
    expect($payload['findings'])->toHaveCount(1);

    $finding = $payload['findings'][0];

    expect($finding['rule'])->toHaveKeys(['title', 'description', 'remediation', 'cwe']);
    expect($finding['rule']['cwe'])->toBe('CWE-79');
    expect($finding['location'])->toHaveKeys(['file', 'line', 'column']);
    expect($finding['fingerprint'])->toMatch('/^[0-9a-f]{16}$/');
});

it('carries kinds on every trace step so a reader can see where a sanitizer narrowed the set', function (): void {
    $payload = json_decode(
        (new JsonReporter())->render(reportableScan(), new ReportOptions()),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    foreach ($payload['findings'][0]['trace'] as $step) {
        expect($step)->toHaveKeys(['step', 'verb', 'file', 'line', 'column', 'snippet', 'description', 'kinds']);
        expect($step['kinds'])->not->toBeEmpty();
    }

    $verbs = array_column($payload['findings'][0]['trace'], 'verb');

    expect($verbs[0])->toBe('source');
    expect(end($verbs))->toBe('sink');
});

it('produces identical JSON across runs, apart from the duration', function (): void {
    $strip = static function (string $json): array {
        /** @var array{scan: array<string, mixed>} $decoded */
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        unset($decoded['scan']['durationMs']);

        return $decoded;
    };

    $a = $strip((new JsonReporter())->render(reportableScan(), new ReportOptions()));
    $b = $strip((new JsonReporter())->render(reportableScan(), new ReportOptions()));

    expect($a)->toBe($b);
});

it('emits SARIF 2.1.0 with populated code flows', function (): void {
    // Emitting SARIF without codeFlows wastes the format: it degrades to a
    // flat list no better than the console output.
    $payload = json_decode(
        (new SarifReporter())->render(reportableScan(), new ReportOptions()),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    expect($payload['version'])->toBe('2.1.0');
    expect($payload['$schema'])->toContain('sarif-schema-2.1.0');

    $run = $payload['runs'][0];

    expect($run['tool']['driver']['name'])->toBe('wp-taint');
    expect($run['originalUriBaseIds'])->toHaveKey('SRCROOT');

    $result = $run['results'][0];
    $locations = $result['codeFlows'][0]['threadFlows'][0]['locations'];

    expect($locations)->not->toBeEmpty();

    foreach ($locations as $location) {
        expect($location['nestingLevel'])->toBe(0);
        expect($location['location']['message']['text'])->not->toBeEmpty();
        expect($location['location']['physicalLocation']['region'])->toHaveKey('startLine');
    }
});

it('carries the real severity in SARIF properties, since SARIF has no critical', function (): void {
    $payload = json_decode(
        (new SarifReporter())->render(scanFixture('vulnerable/sqli-wpdb-query-interpolation.php'), new ReportOptions()),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    $result = $payload['runs'][0]['results'][0];

    expect($result['level'])->toBe('error');
    expect($result['properties']['problemSeverity'])->toBe('critical');
    expect($result['properties']['securitySeverity'])->toBe('9.0');
    expect($result['partialFingerprints'])->toHaveKey('wpTaintFingerprint');
});

it('gives every SARIF rule full metadata', function (): void {
    $payload = json_decode(
        (new SarifReporter())->render(reportableScan(), new ReportOptions()),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    foreach ($payload['runs'][0]['tool']['driver']['rules'] as $rule) {
        expect($rule)
            ->toHaveKeys(['id', 'name', 'shortDescription', 'fullDescription', 'help', 'defaultConfiguration']);
        expect($rule['help']['markdown'])->toContain('Remediation');
        expect($rule['properties']['tags'])->toContain('security');
    }
});

it('shows source and sink only by default, and the full trace when verbose', function (): void {
    $reporter = new ConsoleReporter(new Ansi(false));

    $compact = $reporter->render(reportableScan(), new ReportOptions(verbose: false));
    $verbose = $reporter->render(reportableScan(), new ReportOptions(verbose: true));

    expect($compact)->toContain('source');
    expect($compact)->toContain('sink');
    expect($compact)->toContain('--verbose');
    expect($compact)->not->toContain('Suppress');

    expect($verbose)->toContain('Fix');
    expect($verbose)->toContain('Suppress');
    expect($verbose)->toContain('wp-taint-ignore-next-line');
    expect(strlen($verbose))->toBeGreaterThan(strlen($compact));
});

it('emits no ANSI codes when colour is off', function (): void {
    $plain = (new ConsoleReporter(new Ansi(false)))->render(reportableScan(), new ReportOptions(verbose: true));

    expect($plain)->not->toContain("\033[");
});

it('always reports parse failures in the summary footer', function (): void {
    // A silently skipped file is a silent false negative.
    $result = scanCode('<?php this is not php at all {{{');

    $report = (new ConsoleReporter(new Ansi(false)))->render($result, new ReportOptions());

    expect($report)->toContain('failed to parse');
    expect($report)->toContain('--parse-report');
});

it('reports the suppressed count so the debt stays visible', function (): void {
    $result = reportableScan()->withFindings(reportableScan()->findings, 3, 2);

    $report = (new ConsoleReporter(new Ansi(false)))->render($result, new ReportOptions());

    expect($report)->toContain('3 findings suppressed by baseline');
    expect($report)->toContain('2 findings suppressed inline');
});

it('points at a command that exists, with the scope it needs', function (): void {
    // The footer used to read "run with --verbose for the full path, or
    // --explain for why", which is wrong twice: `explain` is a command rather
    // than a scan option, so `scan --explain` fails outright, and without
    // --scope it analyses the one file alone and calls anything clean whose
    // taint arrives through an include or a hook.
    $report = (new ConsoleReporter(new Ansi(false)))->render(reportableScan(), new ReportOptions());

    expect($report)->not->toContain('--explain');
    expect($report)->toContain('wp-taint explain ');
    expect($report)->toContain('--scope=');

    // The hint is a real invocation, so parse it back and run it through the
    // same application the binary uses. A hint that stops working fails here.
    expect($report)->toMatch('/wp-taint explain (\S+):(\d+) --scope=(\S+)/');
    preg_match('/wp-taint explain (\S+):(\d+) --scope=(\S+)/', $report, $matches);

    expect(is_file($matches[1]))->toBeTrue();

    $application = new Enshrined\WpTaint\Cli\Application();
    $application->setAutoExit(false);
    $application->setCatchExceptions(false);

    $tester = new Symfony\Component\Console\Tester\ApplicationTester($application);

    $tester->run([
        'command' => 'explain',
        'location' => $matches[1] . ':' . $matches[2],
        '--scope' => $matches[3],
    ]);

    expect($tester->getStatusCode())->toBe(0);
    expect($tester->getDisplay())->toContain('Taint at this point');
});

it('omits the explain hint when there is nothing to explain', function (): void {
    $report = (new ConsoleReporter(new Ansi(false)))->render(
        scanCode('<?php echo esc_html( $_GET["x"] );'),
        new ReportOptions(),
    );

    expect($report)->not->toContain('wp-taint explain');
});
