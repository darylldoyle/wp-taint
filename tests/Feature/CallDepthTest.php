<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// Taint has no depth limit in either direction. Two bugs made one:
//
// - Down through parameters, a sink more than one call below the function
//   holding the value was dropped, because a summary never passed its callees'
//   sinks on to its own callers.
// - Both ways, functions were resolved in key order, so a chain whose callers
//   sort before their callees moved one level per round and the 32-round cap
//   stopped it at 31 levels, with only a non-convergence warning to show for
//   it. `--jobs` striped the chain across workers and did the same.

/**
 * A chain `depth` calls long, named so every caller sorts before its callee:
 * the order key-sorting handled worst.
 */
function callChain(int $depth, string $direction): string
{
    $name = static fn (int $i): string => sprintf('acme_f%04d', $i);
    $code = "<?php\n";

    if ($direction === 'down') {
        $code .= 'function acme_entry() { ' . $name(1) . "( \$_GET['x'] ); }\n";

        for ($i = 1; $i < $depth; $i++) {
            $code .= 'function ' . $name($i) . '( $v ) { ' . $name($i + 1) . "( \$v ); }\n";
        }

        return $code . 'function ' . $name($depth) . "( \$v ) { echo \$v; }\n";
    }

    $code .= 'function acme_entry() { echo ' . $name(1) . "(); }\n";

    for ($i = 1; $i < $depth; $i++) {
        $code .= 'function ' . $name($i) . '() { return ' . $name($i + 1) . "(); }\n";
    }

    return $code . 'function ' . $name($depth) . "() { return \$_GET['x']; }\n";
}

function scanChainWithJobs(string $code, int $jobs): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-depth-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    $path = $directory . '/chain.php';
    file_put_contents($path, $code);

    try {
        return (new Scanner(testRegistry(), new AnalysisOptions(), $directory, jobs: $jobs))->scan([$path]);
    } finally {
        @unlink($path);
        @rmdir($directory);
    }
}

it('follows a call chain of any depth', function (int $depth, string $direction, int $jobs): void {
    $result = scanChainWithJobs(callChain($depth, $direction), $jobs);

    expect($result->warnings)->toBeEmpty();
    expect($result->findings->all())->toHaveCount(1);
    expect($result->findings->all()[0]->ruleId)->toBe('wp.xss.unescaped-output');
})->with([
    'down, 20' => [20, 'down', 1],
    'down, 50' => [50, 'down', 1],
    'down, 100' => [100, 'down', 1],
    'down, 250' => [250, 'down', 1],
    'up, 20' => [20, 'up', 1],
    'up, 50' => [50, 'up', 1],
    'up, 100' => [100, 'up', 1],
    'up, 250' => [250, 'up', 1],
    'down, 100, four workers' => [100, 'down', 4],
    'up, 100, four workers' => [100, 'up', 4],
]);

it('credits an escaper partway down the chain', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_top() { acme_d1( $_GET['x'] ); }
        function acme_d1( $v ) { acme_d2( esc_html( $v ) ); }
        function acme_d2( $v ) { acme_d3( $v ); }
        function acme_d3( $v ) { echo $v; }
        PHP);

    expect($result->findings)->toBeEmpty();
});

it('follows a value passed down into a hook callback through a helper', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_submit() { acme_notify( $_POST['entry'] ); }
        function acme_notify( $entry ) { do_action( 'acme_after_submission', $entry ); }
        function acme_after_submission( $entry ) { echo $entry; }
        add_action( 'acme_after_submission', 'acme_after_submission' );
        PHP);

    $findings = $result->findings->all();

    expect($findings)->toHaveCount(1);
    expect($findings[0]->line)->toBe(4);
});

it('terminates on a recursive chain that reaches a sink', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_top() { acme_walk( $_GET['x'], 3 ); }
        function acme_walk( $v, $n ) {
            if ( $n > 0 ) { acme_walk( $v, $n - 1 ); return; }
            acme_leaf( $v );
        }
        function acme_leaf( $v ) { echo $v; }
        PHP);

    expect($result->findings->all())->toHaveCount(1);
});
