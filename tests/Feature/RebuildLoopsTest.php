<?php

declare(strict_types=1);

// A loop that rebuilds an array key by key, `$out[ $k ] = f( $v )`, keeps each
// element under its own key. So does a function that rebuilds its parameter
// that way, WordPress code's usual way to sanitise or convert every value.

/**
 * @return list<string> rule@line for each finding
 */
function rebuildFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps each element under its key through a loop that rebuilds the array', function (): void {
    expect(rebuildFindings(<<<'PHP'
        function acme_show() {
            $raw = array( 'name' => $_GET['n'], 'mode' => 'grid' );
            $out = array();
            foreach ( $raw as $k => $v ) {
                $out[ $k ] = trim( $v );
            }
            echo $out['mode'];
            echo $out['name'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('puts what came from elsewhere under every key', function (): void {
    // A value from an inner loop, and one from outside the loop, could be
    // under any key the write names.
    expect(rebuildFindings(<<<'PHP'
        function acme_nested() {
            $rows = array( 'a' => 1, 'b' => 2 );
            $meta = array( 'p' => $_GET['p'], 'q' => 'fixed' );
            $out = array();
            foreach ( $rows as $k => $row ) {
                foreach ( $meta as $j => $m ) {
                    $out[ $k ] = $m;
                }
            }
            echo $out['a'];
        }
        function acme_prefixed() {
            $raw = array( 'name' => 'x', 'mode' => 'grid' );
            $prefix = $_GET['x'];
            $out = array();
            foreach ( $raw as $k => $v ) {
                $out[ $k ] = $prefix . $v;
            }
            echo $out['mode'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@11', 'wp.xss.unescaped-output@20']);
});

it('hands each element back under its key from a function that rebuilds its parameter', function (): void {
    expect(rebuildFindings(<<<'PHP'
        function acme_clean( $input ) {
            $output = array();
            foreach ( $input as $key => $value ) {
                $output[ $key ] = trim( $value );
            }
            return $output;
        }
        function acme_show() {
            $clean = acme_clean( array( 'name' => $_GET['n'], 'mode' => 'grid' ) );
            echo $clean['mode'];
            echo $clean['name'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@12']);
});

it('keeps the keys of a value converted element by element or as a whole', function (): void {
    // elFinder's convEnc(): an array is rebuilt element by element, recursing,
    // and anything else is converted as a string.
    expect(rebuildFindings(<<<'PHP'
        function acme_conv( $var ) {
            if ( is_array( $var ) ) {
                $ret = array();
                foreach ( $var as $k => $v ) {
                    $ret[ $k ] = acme_conv( $v );
                }
                $var = $ret;
            } else {
                $converted = false;
                if ( is_string( $var ) ) {
                    $converted = iconv( 'UTF-8', 'UTF-8//TRANSLIT', $var );
                }
                if ( $converted !== false ) {
                    $var = $converted;
                }
            }
            return $var;
        }
        function acme_show() {
            $stat = acme_conv( array( 'name' => $_GET['n'], 'hash' => 'fixed' ) );
            echo $stat['hash'];
            echo $stat['name'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@23']);
});

it('keeps an array\'s elements apart through a check of its type', function (): void {
    expect(rebuildFindings(<<<'PHP'
        function acme_show() {
            $settings = array( 'id' => 'fixed', 'label' => $_GET['l'] );
            if ( is_array( $settings ) ) {
                echo $settings['id'];
                echo $settings['label'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});
