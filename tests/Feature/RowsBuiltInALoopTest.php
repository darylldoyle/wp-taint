<?php

declare(strict_types=1);

// A function that builds a row per element of its parameter, under the
// element's key, hands each row back with its fields apart. The record of
// what comes back under each key holds kinds, not structure, so a row
// flattened into it put the title's taint under every field.

/**
 * @return list<string> rule@line for each finding
 */
function rowsBuiltInALoopFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps a fixed field of a row built in a loop clean', function (): void {
    expect(rowsBuiltInALoopFindings(<<<'PHP'
        function acme_rows( $posts ) {
            $items = array();
            foreach ( $posts as $i => $post ) {
                $items[ $i ] = array( 'title' => $post['t'], 'color' => 'red' );
            }
            return $items;
        }
        function acme_show() {
            foreach ( acme_rows( get_option( 'rows' ) ) as $item ) {
                echo $item['color'];
                echo $item['title'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@12']);
});

it('still hands each element back whole when the loop writes it as it came', function (): void {
    expect(rowsBuiltInALoopFindings(<<<'PHP'
        function acme_trim( $rows ) {
            $out = array();
            foreach ( $rows as $key => $row ) {
                $out[ $key ] = trim( $row );
            }
            return $out;
        }
        function acme_show() {
            $clean = acme_trim( array( 'a' => 'x', 'b' => $_GET['b'] ) );
            echo $clean['a'];
            echo $clean['b'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@12']);
});
