<?php

declare(strict_types=1);

// A by-reference loop writes each item back into the collection. It went
// back as one set, so every value an item held reached every key of every
// item. Each item now goes back with its own parts.

/**
 * @return list<string> rule@line for each finding
 */
function byReferenceLoopFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('writes each item back with its own parts', function (): void {
    expect(byReferenceLoopFindings(<<<'PHP'
        function acme_rows() {
            $rows = array( array( 'data' => array( 'a' => 'x' ), 'note' => get_option( 'n' ) ) );
            foreach ( $rows as &$row ) {
                $row['data'] = array_intersect_key( $row['data'], array( 'a' => 1 ) );
            }
            foreach ( $rows as $row ) {
                echo implode( ',', array_keys( $row['data'] ) );
                echo $row['note'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('still carries what the loop writes', function (): void {
    expect(byReferenceLoopFindings(<<<'PHP'
        function acme_rows() {
            $list = array( 'a' );
            foreach ( $list as &$value ) {
                $value = $_GET['v'];
            }
            echo $list[0];
        }
        PHP))->toBe(['wp.xss.unescaped-output@7']);
});
