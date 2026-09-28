<?php

declare(strict_types=1);

// A column or table name cannot be passed to prepare(), so code escapes it
// for the backticks it will sit in: every backtick doubled, or removed. A
// str_replace() that escaped the backslash and then both quotes is the other
// hand-written escaper. Both returned their subject as raw as before.

/**
 * @return list<string> rule@line for each finding
 */
function identifierEscapeFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('credits an identifier escaped for the backticks it sits in', function (string $replace): void {
    // Not an injection. The request still chooses the name, which is its own
    // finding: see IdentifierChoiceTest.
    expect(identifierEscapeFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$col = str_replace( '`', {$replace}, \$_GET['col'] );
            \$wpdb->get_results( "SELECT `\$col` FROM t" );
            \$wpdb->get_results( 'SELECT `' . \$col . '` FROM t' );
        }
        PHP))->toBe(['wp.sqli.identifier-choice@5', 'wp.sqli.identifier-choice@6']);
})->with([
    'doubled' => ["'``'"],
    'removed' => ["''"],
]);

it('reports an identifier escaped for backticks and placed outside them', function (): void {
    expect(identifierEscapeFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $col = str_replace( '`', '``', $_GET['col'] );
            $wpdb->get_results( "SELECT $col FROM t" );
            $wpdb->get_results( "SELECT * FROM t WHERE name = '$col'" );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@5', 'wp.sqli.wpdb-query@6']);
});

it('credits a replacement that escapes the backslash and then both quotes, inside quotes', function (): void {
    expect(identifierEscapeFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = str_replace( array( '\\', "'", '"' ), array( '\\\\', "\\'", '\\"' ), $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
            $wpdb->query( "DELETE FROM t WHERE id = $v" );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@6']);
});

it('does not credit the quotes escaped before the backslash', function (): void {
    // Doubling the backslash last turns the \' just written into \\', which
    // ends the literal.
    expect(identifierEscapeFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = str_replace( array( "'", '"', '\\' ), array( "\\'", '\\"', '\\\\' ), $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@5']);
});

it('does not credit a replacement that escapes one quote', function (): void {
    expect(identifierEscapeFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE name = \"$v\"" );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@5']);
});

it('reports an identifier escaped for backticks that a callee places bare', function (): void {
    expect(identifierEscapeFindings(<<<'PHP'
        function acme_select( $col ) {
            global $wpdb;
            return $wpdb->get_results( "SELECT $col FROM t" );
        }
        function acme_run() {
            acme_select( str_replace( '`', '``', $_GET['col'] ) );
        }
        PHP))->toContain('wp.sqli.unprepared-query@4');
});
