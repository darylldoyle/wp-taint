<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\InternalTypes;

// A property read on a value of unknown class shares one slot per property
// name with every other such read and write. PHP's own methods declare what
// they return, and a value one of them returned is of that class.

/**
 * @return list<string> rule@line for each finding
 */
function internalTypeFindings(string $body): array
{
    $directory = sys_get_temp_dir() . '/wp-taint-internal-' . bin2hex(random_bytes(6));
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

it('reads the class PHP declares a method to return', function (): void {
    expect(InternalTypes::methodReturnClass('ReflectionFunction', 'getClosureCalledClass'))->toBe('ReflectionClass')
        ->and(InternalTypes::methodReturnClass('\\ReflectionMethod', 'getDeclaringClass'))->toBe('ReflectionClass');
});

it('answers nothing for a union, an interface, a builtin type, or a class that is not PHP\'s', function (): void {
    expect(InternalTypes::methodReturnClass('DateTime', 'modify'))->toBeNull()
        ->and(InternalTypes::methodReturnClass('Exception', 'getPrevious'))->toBeNull()
        ->and(InternalTypes::methodReturnClass('ReflectionClass', 'getName'))->toBeNull()
        ->and(InternalTypes::methodReturnClass(Scanner::class, 'scan'))->toBeNull()
        ->and(InternalTypes::functionReturnClass('simplexml_load_string'))->toBeNull();
});

it('keeps a PHP-typed value out of the slot unresolved writes share', function (): void {
    $findings = internalTypeFindings(<<<'PHP'
        function acme_label( $labels ) {
            $labels->name = $_GET['label'];
        }
        function acme_callable_name( $callable ) {
            $r = new \ReflectionFunction( $callable );
            $class = $r->getClosureCalledClass();
            echo $class->name;
        }
        function acme_other( $thing ) {
            echo $thing->name;
        }
        PHP);

    expect($findings)->not->toContain('wp.xss.unescaped-output@8')
        ->and($findings)->toContain('wp.xss.unescaped-output@11');
});

it('does not type a value as a class the scan extends', function (): void {
    expect(internalTypeFindings(<<<'PHP'
        class Acme_Reflection extends \ReflectionClass {}
        function acme_label( $labels ) {
            $labels->name = $_GET['label'];
        }
        function acme_declaring_name( $method ) {
            $class = $method->getDeclaringClass();
            echo $class->name;
        }
        function acme_typed( \ReflectionMethod $method ) {
            $class = $method->getDeclaringClass();
            echo $class->name;
        }
        PHP))->toContain('wp.xss.unescaped-output@12');
});

it('still follows a method call on a PHP-typed value as a dynamic call', function (): void {
    expect(internalTypeFindings(<<<'PHP'
        function acme_build( $callable ) {
            $r = new \ReflectionFunction( $callable );
            $class = $r->getClosureCalledClass();
            echo $class->newInstance( $_GET['v'] );
        }
        PHP))->toContain('wp.xss.unescaped-output@5');
});
