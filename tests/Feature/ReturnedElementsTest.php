<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A function that builds an array and returns it hands its caller the
// array's elements, under the keys they were written with. Returning only the
// array's own taint lost them: `$a['k'] = $_GET['x']; return $a;` was clean
// to every caller.

/**
 * @return list<string> rule@line for each finding
 */
function returnedElementFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-returned-' . bin2hex(random_bytes(6));
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

it('hands the caller an element written under a literal key, and only under that key', function (): void {
    $findings = returnedElementFindings(<<<'PHP'
        function acme_build() {
            $a = array();
            $a['id'] = 42;
            $a['title'] = $_GET['title'];
            return $a;
        }
        function acme_show() {
            $r = acme_build();
            echo $r['id'];
            echo $r['title'];
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@11')
        ->and($findings)->not->toContain('wp.xss.unescaped-output@10');
});

it('hands the caller an element written under a computed key', function (): void {
    expect(returnedElementFindings(<<<'PHP'
        function acme_build() {
            $a = array();
            $a[] = $_GET['title'];
            return $a;
        }
        function acme_show() {
            $r = acme_build();
            echo $r[0];
        }
        PHP))->toContain('wp.xss.unescaped-output@9');
});

it('does not taint the keys of a returned array built under literal keys', function (): void {
    expect(returnedElementFindings(<<<'PHP'
        function acme_options() {
            $o = array();
            $o['title'] = $_GET['title'];
            return $o;
        }
        function acme_show() {
            foreach ( acme_options() as $name => $value ) {
                echo '<label for="' . $name . '">';
            }
        }
        PHP))->toBe([]);
});

it('hands on only what got through the body into the element', function (): void {
    $findings = returnedElementFindings(<<<'PHP'
        function acme_wrap( $x ) {
            return array( 'v' => $x );
        }
        function acme_show() {
            $raw = acme_wrap( $_GET['a'] );
            echo $raw['v'];
            $escaped = acme_wrap( esc_html( $_GET['b'] ) );
            echo $escaped['v'];
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@7')
        ->and($findings)->not->toContain('wp.xss.unescaped-output@9');
});
