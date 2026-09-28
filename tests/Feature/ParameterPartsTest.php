<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Taint\ParameterParts;

// A function that reads a parameter through different parts can be summarised
// part by part: a stored value beside a literal description is escaped, and
// the description is printed raw.

/**
 * @return array<int, list<string>> each parameter's parts, as text
 */
function partsReadBy(string $body): array
{
    $path = sys_get_temp_dir() . '/wp-taint-parts-' . bin2hex(random_bytes(6)) . '.php';
    file_put_contents($path, "<?php\n" . $body);

    try {
        $parsed = (new CfgBuilder(dirname($path)))->buildFromFile($path)->file();
    } finally {
        unlink($path);
    }

    foreach ($parsed->script->functions as $func) {
        if (str_ends_with(strtolower($func->name), 'acme_f')) {
            return array_map(
                static fn (array $parts): array => array_map(ParameterParts::describe(...), $parts),
                ParameterParts::of($func),
            );
        }
    }

    throw new RuntimeException('acme_f() was not declared.');
}

it('names each part a function reads, through loops and copies', function (): void {
    expect(partsReadBy(<<<'PHP'
        function acme_f( $options, $flag, $atts ) {
            foreach ( $options as $field ) {
                echo esc_attr( $field['value'] );
                $copy = $field;
                echo $copy['desc'];
            }
            if ( $flag ) {
                echo 1;
            }
            foreach ( $atts as $name => $value ) {
                echo $name . '=' . esc_attr( $value );
            }
            echo implode( ',', array_keys( $atts ) );
        }
        PHP))->toBe([
        0 => ['[*]', "[*]['desc']", "[*]['value']"],
        2 => ['#keys', '[*]'],
    ]);
});

it('does not count a write into an element as a read of it', function (): void {
    expect(partsReadBy(<<<'PHP'
        function acme_f( $args ) {
            $args['title'] = 'x';
            $args['nested']['id'] = 1;
            echo $args['label'];
        }
        PHP))->toBe([0 => ["['label']", "['nested']"]]);
});

it('follows a join its inputs agree on, and a computed key', function (): void {
    expect(partsReadBy(<<<'PHP'
        function acme_f( $row, $i ) {
            $cell = $i ? $row['a'] : '';
            echo $cell['b'];
            echo $row[ $i ];
        }
        PHP))->toBe([0 => ["['a']", '[*]', "['a']['b']"]]);
});

/**
 * @return list<string> rule@line for each finding
 */
function partFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('hands each part of an argument only what that part of the parameter reaches', function (): void {
    // WooCommerce's settings fields: each field's value is escaped, and its
    // description is printed as it is. A stored value beside a literal
    // description is not printed raw.
    expect(partFindings(<<<'PHP'
        function acme_fields( $options ) {
            foreach ( $options as $field ) {
                echo '<input value="' . esc_attr( $field['value'] ) . '">';
                echo $field['desc'];
            }
        }
        function acme_stored() {
            acme_fields( array( array( 'value' => get_option( 'acme' ), 'desc' => 'Help text' ) ) );
        }
        PHP))->toBe([]);

    expect(partFindings(<<<'PHP'
        function acme_fields( $options ) {
            foreach ( $options as $field ) {
                echo '<input value="' . esc_attr( $field['value'] ) . '">';
                echo $field['desc'];
            }
        }
        function acme_requested() {
            acme_fields( array( array( 'value' => 'x', 'desc' => $_GET['d'] ) ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@5']);
});

it('tells a parameter\'s keys from its values', function (): void {
    // Elementor and Contact Form 7 render attributes this way: the names are
    // printed as they are, the values escaped.
    expect(partFindings(<<<'PHP'
        function acme_attributes( $atts ) {
            $out = '';
            foreach ( $atts as $name => $value ) {
                $out .= ' ' . $name . '="' . esc_attr( $value ) . '"';
            }
            return $out;
        }
        function acme_show() {
            echo acme_attributes( array( 'title' => $_GET['t'] ) );
            echo acme_attributes( array( $_GET['k'] => 'v' ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@11']);
});

it('keeps a part through a helper the function hands it to', function (): void {
    expect(partFindings(<<<'PHP'
        function acme_label( $field ) {
            return $field['label'];
        }
        function acme_row( $field ) {
            echo esc_html( $field['value'] );
            echo acme_label( $field );
        }
        function acme_show() {
            acme_row( array( 'value' => $_GET['v'], 'label' => 'Name' ) );
            acme_row( array( 'value' => 'x', 'label' => $_GET['l'] ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@7']);
});
