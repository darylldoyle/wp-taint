<?php

declare(strict_types=1);

// Escaping a column name for its backticks keeps it one identifier. It does
// not stop the request choosing which one: `user_pass` as readily as
// `post_title`. That is its own, lesser finding. A fixed list settles it.

/**
 * @return list<string> rule@line for each finding
 */
function identifierChoiceFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('reports a request value that names a column inside backticks', function (string $escape): void {
    expect(identifierChoiceFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$col = {$escape};
            \$wpdb->get_results( "SELECT `\$col` FROM t" );
        }
        PHP))->toBe(['wp.sqli.identifier-choice@5']);
})->with([
    'backticks doubled' => ["str_replace( '`', '``', \$_GET['col'] )"],
    'a key' => ["sanitize_key( \$_GET['col'] )"],
]);

it('does not report a name a fixed list settles', function (): void {
    expect(identifierChoiceFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $col = $_GET['col'];
            if ( in_array( $col, array( 'date', 'title' ), true ) ) {
                $wpdb->get_results( "SELECT `$col` FROM t" );
            }
        }
        PHP))->toBe([]);
});

it('lets an injectable name report as the injection', function (): void {
    expect(identifierChoiceFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $col = esc_sql( $_GET['col'] );
            $wpdb->get_results( "SELECT `$col` FROM t" );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@5']);
});
