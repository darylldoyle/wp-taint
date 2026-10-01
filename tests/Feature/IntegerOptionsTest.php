<?php

declare(strict_types=1);

// WordPress casts some options to integers before it saves them, so reading
// one hands back a number. WooCommerce's report stores put
// get_option( 'posts_per_page' ) into a LIMIT clause.

/**
 * @return list<string> rule@line for each SQL finding
 */
function integerOptionFindings(string $body): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . $body)),
        static fn (string $finding): bool => str_starts_with($finding, 'wp.sqli.'),
    ));
}

it('reads an option WordPress saves as an integer as clean', function (): void {
    expect(integerOptionFindings(<<<'PHP'
        function acme_recent() {
            global $wpdb;
            return $wpdb->get_results( 'SELECT id FROM t LIMIT ' . get_option( 'posts_per_page' ) );
        }
        PHP))->toBe([]);
});

it('still reads an option saved as text as stored data', function (): void {
    expect(integerOptionFindings(<<<'PHP'
        function acme_recent() {
            global $wpdb;
            return $wpdb->get_results( 'SELECT id FROM t LIMIT ' . get_option( 'acme_per_page' ) );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@4']);
});

it('reads a request value saved to an integer option as clean', function (): void {
    expect(integerOptionFindings(<<<'PHP'
        function acme_save() {
            update_option( 'posts_per_page', $_POST['n'] );
        }
        function acme_recent() {
            global $wpdb;
            return $wpdb->get_results( 'SELECT id FROM t LIMIT ' . get_option( 'posts_per_page' ) );
        }
        PHP))->toBe([]);
});

it('still reads a name that may be a text option as stored data', function (): void {
    expect(integerOptionFindings(<<<'PHP'
        function acme_recent( $rss ) {
            global $wpdb;
            $name = $rss ? 'posts_per_rss' : 'acme_per_page';
            return $wpdb->get_results( 'SELECT id FROM t LIMIT ' . get_option( $name ) );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@5']);
});
