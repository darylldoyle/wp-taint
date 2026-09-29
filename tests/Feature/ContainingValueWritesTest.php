<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// An element write lands on the temporary the fetch before it produced, which
// nothing reads again, so `$a['x']['y'] = $_GET['v']` went nowhere. An element
// write into a property still stops at the property: stage 3c.

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
