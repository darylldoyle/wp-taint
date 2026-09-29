<?php

declare(strict_types=1);

// A returned array keeps its structure at the caller, to the depth a shape
// keeps: `$r['general']['mode']` reads only what the callee put there.

/**
 * @return list<string> rule@line for each finding
 */
function returnShapeFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps a returned array nested', function (): void {
    expect(returnShapeFindings(<<<'PHP'
        function acme_settings() {
            return array( 'general' => array( 'title' => $_GET['t'], 'mode' => 'grid' ) );
        }
        function acme_show() {
            $settings = acme_settings();
            echo $settings['general']['mode'];
            echo $settings['general']['title'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});

it('keeps what a parameter brings back nested', function (): void {
    expect(returnShapeFindings(<<<'PHP'
        function acme_field( $value ) {
            return array( 'field' => array( 'value' => $value, 'label' => 'Name' ) );
        }
        function acme_show() {
            $field = acme_field( $_GET['v'] );
            echo $field['field']['label'];
            echo $field['field']['value'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});

it('keeps a nested array through a chain of returns', function (): void {
    expect(returnShapeFindings(<<<'PHP'
        function acme_inner() {
            $out = array( 'row' => array( 'raw' => $_GET['r'], 'id' => 7 ) );
            return $out;
        }
        function acme_outer() {
            return acme_inner();
        }
        function acme_show() {
            $data = acme_outer();
            echo $data['row']['id'];
            echo $data['row']['raw'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@12']);
});

it('keeps the structure of what a callback returns into array_map()', function (): void {
    expect(returnShapeFindings(<<<'PHP'
        function acme_row( $value ) {
            return array( 'raw' => $value, 'label' => 'Row' );
        }
        function acme_show() {
            $rows = array_map( 'acme_row', $_GET['list'] );
            foreach ( $rows as $row ) {
                echo $row['label'];
                echo $row['raw'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('still reports what a returned array holds under a computed key', function (): void {
    // A computed key could be any of them, so every read sees it.
    expect(returnShapeFindings(<<<'PHP'
        function acme_by_key( $key ) {
            $out = array( 'safe' => array( 'id' => 1 ) );
            $out[ $key ] = $_GET['i'];
            return $out;
        }
        function acme_show( $name ) {
            $data = acme_by_key( $name );
            echo $data['safe']['id'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});
