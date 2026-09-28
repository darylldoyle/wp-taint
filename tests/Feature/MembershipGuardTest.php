<?php

declare(strict_types=1);

// `in_array( $x, $list, true )` makes `$x` one of `$list`'s values. A list the
// code built itself settles the value as a literal list does, as long as the
// list carries no taint.

/**
 * @return list<string> rule@line for each finding
 */
function membershipGuardFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('settles a value found in a list the code built itself', function (): void {
    expect(membershipGuardFindings(<<<'PHP'
        function acme_defaults() {
            return array( 'colour' => 'red', 'size' => 'm' );
        }
        function acme_choose() {
            $allowed = array_keys( acme_defaults() );
            $key = $_GET['key'];
            if ( in_array( $key, $allowed, true ) ) {
                echo $key;
            }
            $request_list = explode( ',', $_GET['list'] );
            if ( in_array( $key, $request_list, true ) ) {
                echo $key;
            }
            if ( in_array( $key, $allowed ) ) {
                echo $key;
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@13', 'wp.xss.unescaped-output@16']);
});

it('settles a key a loop skips unless the code knows it', function (): void {
    // WooCommerce's REST settings controllers check each setting a request
    // names against the ids of their own definitions before saving it.
    expect(membershipGuardFindings(<<<'PHP'
        function acme_defaults() {
            return array( 'colour' => 'red', 'size' => 'm' );
        }
        function acme_save_all() {
            $allowed = array_keys( acme_defaults() );
            foreach ( (array) $_POST['settings'] as $name => $value ) {
                $name = sanitize_text_field( $name );
                if ( ! in_array( $name, $allowed, true ) ) {
                    continue;
                }
                update_option( $name, sanitize_text_field( $value ) );
            }
        }
        PHP))->toBe([]);
});
