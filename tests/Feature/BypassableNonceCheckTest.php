<?php

declare(strict_types=1);

// `isset( $n ) && ! wp_verify_nonce( $n )` is false when the request sends no
// nonce, so a denial guarded by it alone never runs. It is a bypass only when
// nothing else stops that request: the condition around the conjunction, or
// an earlier branch that ends the function. See issue 8.

/**
 * @return list<int> the lines the rule reports, for a function body
 */
function bypassableNonceLines(string $body): array
{
    $source = "<?php\nfunction acme_save() {\n" . $body . "\n\tupdate_option( 'acme', 1 );\n}\n";
    $lines = [];

    foreach (scanCode($source)->findings->all() as $finding) {
        if ($finding->ruleId === 'wp.csrf.bypassable-nonce-check') {
            $lines[] = $finding->line;
        }
    }

    return $lines;
}

it('stays quiet when the missing nonce is handled anyway', function (string $body): void {
    expect(bypassableNonceLines($body))->toBe([]);
})->with([
    // The reporter's shape, from issue 8.
    'missing, or present and wrong' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) {
            return false;
        }
        PHP],
    'empty() for the missing nonce' => [<<<'PHP'
        if ( empty( $_POST['n'] ) || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) {
            wp_die();
        }
        PHP],
    'the same test inside a negation' => [<<<'PHP'
        if ( ! ( ! isset( $_POST['n'] ) || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) ) {
            update_option( 'acme', 2 );
        }
        PHP],
    'another denial beside it' => [<<<'PHP'
        if ( ! current_user_can( 'manage_options' ) || ! isset( $_POST['n'] )
            || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) {
            wp_die();
        }
        PHP],
    'an earlier return' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) ) {
            return;
        }
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        PHP],
    'an earlier wp_send_json_error()' => [<<<'PHP'
        if ( empty( $_POST['n'] ) ) {
            wp_send_json_error();
        }
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_send_json_error();
        }
        PHP],
    'an earlier branch of the same if' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) ) {
            exit;
        } elseif ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            exit;
        }
        PHP],
    'an earlier throw' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) ) {
            throw new Exception( 'no nonce' );
        }
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        PHP],
    'an earlier return, outside the block' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) ) {
            return;
        }
        if ( 'save' === $_POST['do'] ) {
            if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
                wp_die();
            }
        }
        PHP],
]);

it('still reports a check that a missing nonce skips', function (string $body, int $line): void {
    expect(bypassableNonceLines($body))->toBe([$line]);
})->with([
    'the plain shape' => [<<<'PHP'
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        PHP, 3],
    // `&&` binds tighter, so a missing nonce leaves only the capability check.
    'or a capability check' => [<<<'PHP'
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) || ! current_user_can( 'manage_options' ) ) {
            wp_die();
        }
        PHP, 3],
    'and a missing nonce' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) && ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) {
            wp_die();
        }
        PHP, 3],
    'a different parameter missing' => [<<<'PHP'
        if ( ! isset( $_POST['other'] ) || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) ) {
            wp_die();
        }
        PHP, 3],
    'an earlier branch that does not stop' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) ) {
            error_log( 'no nonce' );
        }
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        PHP, 6],
    'an earlier branch that is not certain' => [<<<'PHP'
        if ( ! isset( $_POST['n'] ) && 'save' === $_POST['do'] ) {
            return;
        }
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        PHP, 6],
    'an earlier branch that follows the check' => [<<<'PHP'
        if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            wp_die();
        }
        if ( ! isset( $_POST['n'] ) ) {
            return;
        }
        PHP, 3],
    // Continue leaves the loop body, and the save after the loop still runs.
    'an earlier continue' => [<<<'PHP'
        foreach ( array( 1 ) as $i ) {
            if ( ! isset( $_POST['n'] ) ) {
                continue;
            }
            if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
                wp_die();
            }
        }
        PHP, 7],
    // The catch takes the throw, and the save after the try still runs.
    'a throw that a try can catch' => [<<<'PHP'
        try {
            if ( ! isset( $_POST['n'] ) ) {
                throw new Exception( 'no nonce' );
            }
            if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
                wp_die();
            }
        } catch ( Exception $e ) {
            error_log( $e->getMessage() );
        }
        PHP, 7],
    // A branch before the one that exits could be taken instead, and fall through.
    'an exit behind an uncertain branch' => [<<<'PHP'
        if ( 'save' === $_POST['do'] ) {
            error_log( 'save' );
        } elseif ( ! isset( $_POST['n'] ) ) {
            exit;
        } elseif ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'a' ) ) {
            exit;
        }
        PHP, 7],
]);
