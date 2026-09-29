<?php

declare(strict_types=1);

// wp_parse_args() merges a caller's values over the defaults, key by key, and
// wp_list_pluck() reads one field of each row. Both returned clean before.

/**
 * @return list<string> rule@line for each finding
 */
function wordpressArrayHelperFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps each key apart through wp_parse_args()', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_box() {
            $args = wp_parse_args( array( 'title' => $_GET['t'] ), array( 'title' => '', 'label' => 'Box' ) );
            echo $args['label'];
            echo $args['title'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@5']);
});

it('hands a caller\'s value through wp_parse_args() in the callee, under its own key', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_box( $args ) {
            $args = wp_parse_args( $args, array( 'title' => '', 'label' => 'Box' ) );
            echo $args['label'];
            echo $args['title'];
        }
        function acme_page() {
            acme_box( array( 'title' => $_GET['t'] ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@5']);
});

it('does not print a key the callee only compares', function (): void {
    // Custom Post Type UI's select input: the selected value picks an option,
    // and only the options are printed.
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_select( $args ) {
            $args = wp_parse_args( $args, array( 'options' => array(), 'selected' => '' ) );
            foreach ( $args['options'] as $option ) {
                $on = $args['selected'] === $option ? ' selected' : '';
                echo '<option' . $on . '>' . $option . '</option>';
            }
        }
        function acme_page() {
            acme_select( array( 'options' => array( 'a', 'b' ), 'selected' => $_GET['s'] ) );
            acme_select( array( 'options' => array( $_GET['o'] ), 'selected' => 'a' ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});

it('still reads a query string the callee parses', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_box( $args ) {
            $args = wp_parse_args( $args, array( 'title' => '' ) );
            echo $args['title'];
        }
        function acme_page() {
            acme_box( $_GET['q'] );
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('follows a parameter into array_merge() under its own keys', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_box( $args ) {
            $args = array_merge( array( 'title' => '', 'label' => 'Box' ), $args );
            echo $args['label'];
            echo $args['title'];
            foreach ( $args as $value ) {
                echo $value;
            }
        }
        function acme_page() {
            acme_box( array( 'title' => $_GET['t'] ) );
            acme_box( array( 'extra' => $_GET['e'] ) );
        }
        PHP))->toBe(['wp.xss.unescaped-output@5', 'wp.xss.unescaped-output@7']);
});

it('reads a query string wp_parse_args() parses as the text it was', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_query() {
            $args = wp_parse_args( $_SERVER['QUERY_STRING'], array( 'page' => 1 ) );
            echo $args['page'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('reads only the field wp_list_pluck() names', function (): void {
    expect(wordpressArrayHelperFindings(<<<'PHP'
        function acme_titles() {
            $rows = array( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            foreach ( wp_list_pluck( $rows, 'title' ) as $title ) {
                echo $title;
            }
            foreach ( wp_list_pluck( $rows, 'raw' ) as $raw ) {
                echo $raw;
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});
