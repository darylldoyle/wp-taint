<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A value typed on every way into a join keeps its type through it. Twig
// assigns a ReflectionClass inside an `&&` and reads its name after, and the
// read fell to the slot every unresolved `->name` shares.

/**
 * @return list<string> rule@line for each finding
 */
function ownerJoinFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-joins-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents(
        $directory . '/plugin.php',
        "<?php\nfunction acme_label( \$labels ) {\n    \$labels->name = \$_GET['label'];\n}\n" . $body,
    );

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

it('keeps a type assigned inside a condition', function (): void {
    expect(ownerJoinFindings(<<<'PHP'
        function acme_name( $callable, $on ) {
            $r = new \ReflectionFunction( $callable );
            if ( $on && ( $class = $r->getClosureCalledClass() ) ) {
                echo $class->name;
            }
        }
        PHP))->toBe([]);
});

it('keeps a type assigned on one branch of a variable that starts as null', function (): void {
    expect(ownerJoinFindings(<<<'PHP'
        function acme_name( $callable, $on ) {
            $r = null;
            if ( $on ) {
                $r = new \ReflectionFunction( $callable );
            }
            echo $r->name;
        }
        PHP))->toBe([]);
});

it('does not type a join whose other side the scan cannot see', function (string $before): void {
    expect(ownerJoinFindings(<<<PHP
        function acme_name( \$callable, \$on ) {
            {$before}
            \$r = new \\ReflectionFunction( \$callable );
            if ( \$on && ( \$class = \$r->getClosureCalledClass() ) ) {
                echo \$class->name;
            }
            echo \$class->name;
        }
        PHP))->toContain('wp.xss.unescaped-output@9')->toContain('wp.xss.unescaped-output@11');
})->with([
    'filled by a call' => 'acme_fill( $class );',
    'a global' => 'global $class;',
    'a static' => 'static $class;',
    'extract()' => 'extract( $_GET );',
    'a reference' => '$alias = &$class;',
]);

it('does not type a join of two classes', function (): void {
    expect(ownerJoinFindings(<<<'PHP'
        function acme_name( $callable, $on, $other ) {
            $r = $on ? new \ReflectionFunction( $callable ) : $other;
            echo $r->name;
        }
        PHP))->toContain('wp.xss.unescaped-output@7');
});
