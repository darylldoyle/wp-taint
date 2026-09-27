<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A guard that checks a value against a safe set, and what it covers: the
// right-hand side of && and ||, an element under a literal key, a normalised
// copy, and the value once it is concatenated, assigned or passed on.

/**
 * @return list<string> rule@line for each finding
 */
function guardFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-guard-' . bin2hex(random_bytes(6));
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

it('credits a check on the right-hand side of &&', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            $id = $_GET['id'];
            if ( isset( $id ) && ctype_digit( $id ) ) {
                echo $id;
            }
        }
        PHP))->toBe([]);
});

it('credits a check on the right-hand side of || that returns early', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            $id = $_GET['id'];
            if ( ! isset( $id ) || ! ctype_digit( $id ) ) {
                return;
            }
            echo $id;
        }
        PHP))->toBe([]);
});

it('learns nothing from the edge of && where the left-hand side may have failed', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            $name = $_GET['name'];
            if ( isset( $name ) && preg_match( '/[<>"]/', $name ) ) {
                return;
            }
            echo $name;
        }
        PHP))->toContain('wp.xss.unescaped-output@7');
});

it('credits a check on an element under a literal key', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            if ( ctype_digit( $_GET['id'] ) ) {
                echo $_GET['id'];
            }
        }
        PHP))->toBe([]);
});

it('credits a guarded value where it is concatenated into a query', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_delete() {
            global $wpdb;
            $id = $_GET['id'];
            if ( ctype_digit( $id ) ) {
                $wpdb->query( 'DELETE FROM t WHERE id = ' . $id );
            }
        }
        PHP))->toBe([]);
});

it('does not credit a check on one key for another', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            if ( ctype_digit( $_GET['id'] ) ) {
                echo $_GET['name'];
            }
        }
        PHP))->toContain('wp.xss.unescaped-output@4');
});

it('does not credit a check the other branch into the same block never made', function (): void {
    // The branch where ctype_digit() failed sets something else and falls
    // into the echo. Only the branch where it passed checked $x.
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            $x = $_GET['x'];
            if ( ! ctype_digit( $x ) ) {
                $y = 1;
            }
            echo $x;
        }
        PHP))->toContain('wp.xss.unescaped-output@7');
});

it('credits a check whose failing branch dies', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_show() {
            $x = $_GET['x'];
            if ( ! ctype_digit( $x ) ) {
                wp_die( 'Bad id' );
            }
            echo $x;
        }
        PHP))->toBe([]);
});

it('credits a check whose failing branch replaces the value with a literal', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_mode() {
            $mode = $_GET['mode'];
            if ( ! in_array( $mode, array( 'grid', 'list' ), true ) ) {
                $mode = 'grid';
            }
            echo $mode;
        }
        PHP))->toBe([]);
});

it('does not credit a check whose failing branch replaces the value with other input', function (): void {
    expect(guardFindings(<<<'PHP'
        function acme_mode() {
            $mode = $_GET['mode'];
            if ( ! in_array( $mode, array( 'grid', 'list' ), true ) ) {
                $mode = $_GET['fallback'];
            }
            echo $mode;
        }
        PHP))->toContain('wp.xss.unescaped-output@7');
});

it('credits a check whose failing branch dies, inside a namespace', function (): void {
    expect(guardFindings(<<<'PHP'
        namespace Acme;
        function show() {
            $x = $_GET['x'];
            if ( ! ctype_digit( $x ) ) {
                wp_die( 'Bad id' );
            }
            echo $x;
        }
        PHP))->toBe([]);
});
