<?php

declare(strict_types=1);

// A read under a key the resolver names every value of reads those elements,
// not any: a class constant, a join of literals, a loop over a literal list.

/**
 * @return list<string> rule@line for each finding
 */
function namedKeyFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('reads only the elements a loop over a literal list visits', function (): void {
    // WP File Manager's volume init rewrites four path options this way.
    expect(namedKeyFindings(<<<'PHP'
        function acme_paths() {
            $opts = array( 'path' => '/var/data', 'tmpPath' => '/tmp/acme' );
            $opts['url'] = $_GET['u'];
            foreach ( array( 'path', 'tmpPath' ) as $key ) {
                $opts[ $key ] = trim( $opts[ $key ] );
            }
            echo $opts['path'];
            echo $opts['url'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('reads only the element a class constant names', function (): void {
    expect(namedKeyFindings(<<<'PHP'
        class Acme_Form {
            const ID = 'id';
            const TITLE = 'title';
            public function show() {
                $data = array( 'id' => 7, 'title' => $_GET['t'] );
                echo $data[ self::ID ];
                echo $data[ self::TITLE ];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});

it('still treats a key it cannot name in full as any key', function (): void {
    // One way in names the key and the other does not, so the write could
    // be under any key. A loop over a list something else writes into could
    // visit anything too.
    expect(namedKeyFindings(<<<'PHP'
        function acme_partial( $flag ) {
            $key = $flag ? 'a' : $_GET['k'];
            $data = array();
            $data[ $key ] = $_GET['v'];
            echo $data['b'];
        }
        function acme_grown() {
            $names = array( 'a' );
            $names[] = $_GET['n'];
            $data = array();
            foreach ( $names as $name ) {
                $data[ $name ] = $_GET['v'];
            }
            echo $data['b'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@6', 'wp.xss.unescaped-output@15']);
});
