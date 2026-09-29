<?php

declare(strict_types=1);

// A write under a literal key replaces the element, for a read later in the
// same block with nothing between that could change it. php-cfg keeps one
// operand for the array, so the write used to join what it replaced.

/**
 * @return list<string> rule@line for each finding
 */
function elementOverwriteFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('reads what an overwrite left', function (string $body): void {
    expect(elementOverwriteFindings($body))->toBe([]);
})->with([
    'a local array' => [<<<'PHP'
        function acme_show() {
            $args = array( 'include' => $_GET['i'] );
            $args['include'] = absint( $args['include'] );
            echo $args['include'];
        }
        PHP],
    'a parameter' => [<<<'PHP'
        function acme_show( $args ) {
            $args['include'] = absint( $args['include'] );
            echo $args['include'];
        }
        function acme_page() {
            acme_show( array( 'include' => $_GET['i'] ) );
        }
        PHP],
    'inside a branch' => [<<<'PHP'
        function acme_show() {
            $args = array( 'include' => $_GET['i'], 'x' => 1 );
            if ( ! empty( $args['include'] ) ) {
                $args['include'] = implode( ',', array_map( 'absint', explode( ',', $args['include'] ) ) );
                $args['x']       = 2;
                echo 'IN (' . $args['include'] . ')';
            }
        }
        PHP],
]);

it('still reads the old value where the overwrite may not have run', function (string $body, int $line): void {
    expect(elementOverwriteFindings($body))->toBe(['wp.xss.unescaped-output@' . $line]);
})->with([
    'a write in a branch, read after it' => [<<<'PHP'
        function acme_show( $flag ) {
            $args = array( 'include' => $_GET['i'] );
            if ( $flag ) {
                $args['include'] = absint( $args['include'] );
            }
            echo $args['include'];
        }
        PHP, 7],
    'a computed key written between' => [<<<'PHP'
        function acme_show( $key ) {
            $args = array();
            $args['include'] = 'x';
            $args[ $key ] = $_GET['v'];
            echo $args['include'];
        }
        PHP, 6],
    'a reference to the array' => [<<<'PHP'
        function acme_show() {
            $args = array();
            $alias = &$args;
            $args['include'] = 'x';
            $alias['include'] = $_GET['v'];
            echo $args['include'];
        }
        PHP, 7],
    'a tainted overwrite' => [<<<'PHP'
        function acme_show() {
            $args = array( 'include' => 'x' );
            $args['include'] = $_GET['v'];
            echo $args['include'];
        }
        PHP, 5],
    'a later write of the same key' => [<<<'PHP'
        function acme_show() {
            $args = array();
            $args['include'] = 'x';
            $args['include'] = $_GET['v'];
            echo $args['include'];
        }
        PHP, 6],
]);
