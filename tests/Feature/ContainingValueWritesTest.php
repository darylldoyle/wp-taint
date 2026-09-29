<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// An element write lands on the temporary the fetch before it produced, which
// nothing reads again, so `$a['x']['y'] = $_GET['v']` and
// `$this->opts['k'] = $_GET['v']` both went nowhere.

/**
 * @return list<string> rule@line for each finding
 */
function containingValueFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-containing-' . bin2hex(random_bytes(6));
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

it('carries a nested element write up to the array', function (): void {
    $findings = containingValueFindings(<<<'PHP'
        function acme_show() {
            $a = array();
            $a['x']['y'] = $_GET['v'];
            echo $a['x']['y'];
            echo $a['w'];
            $b = array();
            $b['x'][] = $_GET['v'];
            echo $b['x'][0];
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@5')
        ->and($findings)->toContain('wp.xss.unescaped-output@9')
        ->and($findings)->not->toContain('wp.xss.unescaped-output@6');
});

it('carries a nested element write under a computed key to every key', function (): void {
    expect(containingValueFindings(<<<'PHP'
        function acme_show( $k ) {
            $a = array();
            $a[ $k ]['y'] = $_GET['v'];
            echo $a['anything']['y'];
        }
        PHP))->toContain('wp.xss.unescaped-output@5');
});

it('leaves the array a copy was taken from alone', function (): void {
    expect(containingValueFindings(<<<'PHP'
        function acme_show() {
            $a = array( 'x' => array() );
            $b = $a['x'];
            $b['y'] = $_GET['v'];
            echo $a['x']['y'];
        }
        PHP))->toBe([]);
});

it('carries an element write into a property to the property', function (): void {
    $findings = containingValueFindings(<<<'PHP'
        class Acme_Box {
            private $opts = array();
            public function set() {
                $this->opts['k'] = $_GET['x'];
                echo $this->opts['k'];
            }
            public function show() {
                echo $this->opts['k'];
            }
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@6')
        ->and($findings)->toContain('wp.xss.unescaped-output@9');
});

it('carries a nested element write into a static property to the property', function (): void {
    expect(containingValueFindings(<<<'PHP'
        class Acme_Cache {
            private static $cache = array();
            public static function set( $group ) {
                self::$cache[ $group ]['k'] = $_GET['x'];
            }
            public static function show() {
                echo self::$cache['posts']['k'];
            }
        }
        PHP))->toContain('wp.xss.unescaped-output@8');
});

it('carries a parameter written into a property element to the caller', function (): void {
    expect(containingValueFindings(<<<'PHP'
        class Acme_Box {
            private $opts = array();
            public function set( $value ) {
                $this->opts['k'] = $value;
            }
            public function show() {
                echo $this->opts['k'];
            }
        }
        function acme_run() {
            $box = new Acme_Box();
            $box->set( $_GET['x'] );
            $box->show();
        }
        PHP))->toContain('wp.xss.unescaped-output@8');
});

it('carries an array literal written into an element or a property', function (): void {
    $findings = containingValueFindings(<<<'PHP'
        class Acme_Box {
            private $opts = array();
            public function set() {
                $this->opts = array( 'k' => $_GET['x'] );
            }
            public function show() {
                echo $this->opts['k'];
            }
        }
        function acme_rows() {
            $rows = array();
            $rows[] = array( 'title' => $_GET['title'] );
            foreach ( $rows as $row ) {
                echo $row['title'];
            }
            $a = array();
            $a['x'] = array( 'y' => $_GET['v'] );
            echo $a['x']['y'];
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@8')
        ->and($findings)->toContain('wp.xss.unescaped-output@15')
        ->and($findings)->toContain('wp.xss.unescaped-output@19');
});

it('keeps a property element written under a fixed key apart from the others', function (): void {
    // WooCommerce's SqlQuery::add_sql_clause( $type, $clause ): each clause
    // type reads only what was written under it.
    expect(containingValueFindings(<<<'PHP'
        class Acme_Query {
            private $clauses = array( 'where' => array(), 'order_by' => array() );
            public function add( $type, $clause ) {
                $this->clauses[ $type ][] = $clause;
            }
            public function get( $type ) {
                return implode( ' ', $this->clauses[ $type ] );
            }
        }
        function acme_report() {
            global $wpdb;
            $query = new Acme_Query();
            $query->add( 'where', 'AND status = 1' );
            $query->add( 'order_by', $_GET['orderby'] );
            $wpdb->get_results( 'SELECT id FROM t WHERE 1=1 ' . $query->get( 'where' ) );
            $wpdb->get_results( 'SELECT id FROM t ORDER BY ' . $query->get( 'order_by' ) );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@17']);
});
