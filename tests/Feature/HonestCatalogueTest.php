<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\BlockOrder;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;

// Escapers the catalogue credited for more than they do, or did not list at
// all, and a value fold that answered for a join it could not follow.

/**
 * @return list<string> rule@line for each finding
 */
function honestCatalogueFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-honest-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/plugin.php', "<?php\n" . $body);

    try {
        $result = (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        unlink($directory . '/plugin.php');
        rmdir($directory);
    }

    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->line,
        $result->findings->all(),
    );
}

/**
 * The strings the value `acme_f()` returns can hold, asked both ways.
 *
 * @return array{0: list<string>, 1: list<string>} strings(), knownStrings()
 */
function returnedStrings(string $body): array
{
    $path = sys_get_temp_dir() . '/wp-taint-fold-' . bin2hex(random_bytes(6)) . '.php';
    file_put_contents($path, "<?php\n" . $body);

    try {
        $parsed = (new CfgBuilder(dirname($path)))->buildFromFile($path)->file();
    } finally {
        unlink($path);
    }

    $resolver = new ValueResolver();

    foreach ($parsed->script->functions as $func) {
        if ($func->name !== 'acme_f') {
            continue;
        }

        foreach (BlockOrder::of($func->cfg) as $block) {
            foreach ($block->children as $op) {
                if ($op instanceof Op\Terminal\Return_ && $op->expr !== null) {
                    return [$resolver->strings($op->expr), $resolver->knownStrings($op->expr)];
                }
            }
        }
    }

    throw new RuntimeException('acme_f() returns nothing.');
}

it('does not answer for a join with a branch it cannot follow', function (): void {
    [$exact, $known] = returnedStrings(<<<'PHP'
        function acme_f( $c, $rows ) {
            $v = $c ? "'" : (string) count( $rows );
            return $v;
        }
        PHP);

    expect($exact)->toBe([])->and($known)->toBe(["'"]);
});

it('answers for a join whose every branch folds', function (): void {
    [$exact, $known] = returnedStrings(<<<'PHP'
        function acme_f( $c ) {
            $v = $c ? 'a' : 'b';
            return $v . '_x';
        }
        PHP);

    expect($exact)->toBe(['a_x', 'b_x'])->and($known)->toBe(['a_x', 'b_x']);
});

it('reads a quote from a partly folded join as unknown', function (): void {
    expect(honestCatalogueFindings(<<<'PHP'
        function acme_run( $rows, $c ) {
            global $wpdb;
            $open = $c ? "'" : (string) count( $rows );
            $wpdb->query( "DELETE FROM t WHERE name = " . $open . esc_sql( $_GET['v'] ) . "'" );
        }
        PHP))->toContain('wp.sqli.unprepared-query@5');
});

it('reports a LIKE escaper that escapes no quote', function (string $escaper): void {
    expect(honestCatalogueFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$wpdb->query( "SELECT * FROM t WHERE name LIKE '" . {$escaper}( \$_GET['s'] ) . "'" );
        }
        PHP))->toContain('wp.sqli.wpdb-query@4');
})->with([
    'like_escape' => 'like_escape',
    'wpdb::esc_like' => '$wpdb->esc_like',
]);

it('credits a quote escaper inside quotes only', function (string $escaper): void {
    $findings = honestCatalogueFindings(<<<PHP
        function acme_quoted() {
            global \$wpdb;
            \$wpdb->query( "DELETE FROM t WHERE name = '" . {$escaper}( \$_GET['n'] ) . "'" );
        }
        function acme_bare() {
            global \$wpdb;
            \$wpdb->query( "DELETE FROM t WHERE id = " . {$escaper}( \$_GET['id'] ) );
        }
        PHP);

    expect($findings)->toBe(['wp.sqli.unprepared-query@8']);
})->with([
    'addslashes' => 'addslashes',
    'wpdb::_escape' => '$wpdb->_escape',
    'wpdb::escape' => '$wpdb->escape',
]);

it('reads the value mysqli_real_escape_string() escapes from its second argument', function (): void {
    expect(honestCatalogueFindings(<<<'PHP'
        function acme_quoted( $link ) {
            global $wpdb;
            $wpdb->query( "DELETE FROM t WHERE name = '" . mysqli_real_escape_string( $link, $_GET['n'] ) . "'" );
        }
        PHP))->toBe([]);
});

it('credits _wp_specialchars() in HTML text but not in an attribute', function (): void {
    expect(honestCatalogueFindings(<<<'PHP'
        function acme_text() {
            echo '<p>' . _wp_specialchars( $_GET['a'] ) . '</p>';
        }
        function acme_attribute() {
            echo '<a title="' . _wp_specialchars( $_GET['a'] ) . '">x</a>';
        }
        PHP))->toBe(['wp.xss.unescaped-attribute@6']);
});
