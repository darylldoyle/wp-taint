<?php

declare(strict_types=1);

// A caller's element under a key the callee never names reaches only what
// could read that key: a loop, a computed read, a flatten, a read under a key
// the callee does not name, and what the callee hands back. It does not reach
// the reads of the keys the callee does name.

/**
 * @return list<string> rule@line for each finding
 */
function unnamedElementFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps an element the callee never names away from the keys it reads', function (): void {
    // WooCommerce's settings fields print each field's description raw and
    // hand the whole field on. A stored value under 'options' reached the
    // description through the part for the field itself.
    expect(unnamedElementFindings(<<<'PHP'
        function acme_field_row( $field ) {
            return count( $field );
        }
        function acme_fields( $fields ) {
            foreach ( $fields as $field ) {
                echo $field['desc'];
                echo esc_attr( $field['value'] );
                acme_field_row( $field );
            }
        }
        function acme_page() {
            acme_fields( array( array( 'desc' => 'Text', 'value' => 'v', 'options' => get_option( 'acme' ) ) ) );
        }
        PHP))->toBe([]);
});

it('keeps an unnamed element apart through a helper the callee hands the element to', function (): void {
    // WooCommerce's settings fields: the loop checks for 'desc', and a
    // helper that reads only 'desc' builds the description. The part for the
    // keys the loop does not name reaches only the helper's own such part.
    expect(unnamedElementFindings(<<<'PHP'
        function acme_describe( $field ) {
            return array( 'description' => $field['desc'] );
        }
        function acme_fields( $fields ) {
            foreach ( $fields as $field ) {
                if ( ! isset( $field['desc'] ) ) {
                    continue;
                }
                $described = acme_describe( $field );
                echo esc_attr( $field['value'] ) . $described['description'];
            }
        }
        function acme_page() {
            acme_fields( array( array( 'desc' => 'Text', 'value' => 'v', 'options' => get_option( 'acme' ) ) ) );
        }
        PHP))->toBe([]);
});

it('still reaches a key the next helper names', function (): void {
    expect(unnamedElementFindings(<<<'PHP'
        function acme_options( $field ) {
            echo $field['options'];
        }
        function acme_fields( $fields ) {
            foreach ( $fields as $field ) {
                echo esc_attr( $field['value'] ) . $field['desc'];
                acme_options( $field );
            }
        }
        function acme_page() {
            acme_fields( array( array( 'desc' => 'Text', 'value' => 'v', 'options' => get_option( 'acme' ) ) ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
});

it('hands an element the callee never names back apart from the keys it names', function (): void {
    expect(unnamedElementFindings(<<<'PHP'
        function acme_pick( $args ) {
            echo $args['title'];
            return $args;
        }
        function acme_show() {
            $out = acme_pick( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            echo $out['title'];
            echo $out['raw'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('still reaches every read an unnamed key could be', function (): void {
    // A merge inside the callee puts the caller's 'raw' under a key the
    // callee's defaults also have. A loop sees every element, and a key the
    // caller wrote under a computed key could be the one the callee names.
    expect(unnamedElementFindings(<<<'PHP'
        function acme_merge( $args ) {
            echo $args['title'];
            $all = array_merge( array( 'raw' => '' ), $args );
            echo $all['raw'];
        }
        function acme_loop( $args ) {
            echo $args['title'];
            foreach ( $args as $value ) {
                echo $value;
            }
        }
        function acme_show( $key ) {
            acme_merge( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            acme_loop( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            $computed = array( 'title' => 'Hello' );
            $computed[ $key ] = $_GET['v'];
            acme_pick( $computed );
        }
        function acme_pick( $args ) {
            echo $args['title'];
            return $args;
        }
        PHP))->toBe([
            'wp.xss.unescaped-output@5',
            'wp.xss.unescaped-output@10',
            'wp.xss.unescaped-output@21',
        ]);
});

it('hands each element the callee never names back under its own key', function (): void {
    expect(unnamedElementFindings(<<<'PHP'
        function acme_pick( $args ) {
            echo $args['title'];
            return $args;
        }
        function acme_id( $a ) {
            return $a;
        }
        function acme_show() {
            $out = acme_pick( array( 'title' => 'Hello', 't' => $_GET['t'], 'm' => 'x' ) );
            echo $out['m'];
            echo $out['t'];
            $same = acme_id( array( 't' => $_GET['t'], 'm' => 'x' ) );
            echo $same['m'];
            echo $same['t'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@12', 'wp.xss.unescaped-output@15']);
});

it('keeps each element apart in a property a constructor stores whole', function (): void {
    expect(unnamedElementFindings(<<<'PHP'
        class Acme_Box {
            private $opts;
            public function __construct( $opts ) {
                if ( isset( $opts['mode'] ) ) {
                    $this->opts = $opts;
                }
            }
            public function show() {
                echo $this->opts['name'];
                echo $this->opts['size'];
            }
        }
        function acme_box() {
            $box = new Acme_Box( array( 'mode' => 'grid', 'name' => $_GET['n'], 'size' => 'big' ) );
            $box->show();
        }
        PHP))->toBe(['wp.xss.unescaped-output@10']);
});
