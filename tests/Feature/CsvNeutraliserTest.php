<?php

declare(strict_types=1);

// An apostrophe in front of a formula covers the cell's first character only.
// fputcsv()'s default escape character, a backslash, lets a quote end the cell
// early, and what follows starts a cell the apostrophe does not cover. So the
// neutraliser counts only where the writer passes an empty escape character.

/**
 * @return list<string> kind@line for each CSV finding
 */
function csvNeutraliserFindings(string $body): array
{
    $findings = [];

    foreach (scanCode("<?php\n" . $body)->findings->all() as $finding) {
        if ($finding->ruleId === 'wp.output.csv-injection') {
            $findings[] = $finding->kind->value . '@' . $finding->line;
        }
    }

    return $findings;
}

it('credits an apostrophe only where every quote is doubled', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_export( $out ) {
            $name = preg_replace( '/^([=+\-@])/', "'$1", $_GET['n'] );
            fputcsv( $out, array( $name ), ',', '"', '' );
            fputcsv( $out, array( $name ) );
            fputcsv( $out, array( $name ), ',', '"', '\\' );
            fputcsv( $out, array( $name ), ',', '"', "\0" );
        }
        PHP))->toBe(['csv_prefixed@5', 'csv_prefixed@6', 'csv_prefixed@7']);
});

it('does not credit a tab or a space in front', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_export( $out ) {
            fputcsv( $out, array( preg_replace( '/^([=+\-@])/', "\t$1", $_GET['n'] ) ), ',', '"', '' );
            fputcsv( $out, array( preg_replace( '/^([=+\-@])/', " $1", $_GET['n'] ) ), ',', '"', '' );
        }
        PHP))->toBe(['csv@3', 'csv@4']);
});

it('clears a value with no formula character, whatever the writer', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_export( $out ) {
            fputcsv( $out, array( preg_replace( '/[^a-z0-9]/', '', $_GET['n'] ) ) );
            $name = preg_replace( '/^([=+\-@])/', "'$1", $_GET['n'] );
            fputcsv( $out, array( preg_replace( '/[^a-z0-9]/', '', $name ) ) );
        }
        PHP))->toBe([]);
});

it('keeps the apostrophe through trim() and loses it through substr()', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_export( $out ) {
            $name = preg_replace( '/^([=+\-@])/', "'$1", $_GET['n'] );
            fputcsv( $out, array( trim( $name ) ), ',', '"', '' );
            fputcsv( $out, array( substr( $name, 1 ) ), ',', '"', '' );
        }
        PHP))->toBe(['csv@5']);
});

it('follows the apostrophe out of a helper that adds it', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_cell( $v ) {
            return preg_replace( '/^([=+\-@])/', "'$1", $v );
        }
        function acme_export( $out ) {
            fputcsv( $out, array( acme_cell( $_GET['n'] ) ), ',', '"', '' );
            fputcsv( $out, array( acme_cell( $_GET['n'] ) ) );
        }
        PHP))->toBe(['csv_prefixed@7']);
});

it('follows the apostrophe into a helper that writes the row', function (string $escape, array $expected): void {
    expect(csvNeutraliserFindings(<<<PHP
        function acme_write( \$out, \$row ) {
            fputcsv( \$out, \$row{$escape} );
        }
        function acme_export( \$out ) {
            acme_write( \$out, array( preg_replace( '/^([=+\\-@])/', "'\$1", \$_GET['n'] ) ) );
            acme_write( \$out, array( \$_GET['m'] ) );
        }
        PHP))->toBe($expected);
})->with([
    // A reference inside a callee reports at the callee's line.
    'the default escape' => ['', ['csv_prefixed@3', 'csv@3']],
    'an empty escape' => [", ',', '\"', ''", ['csv@3']],
]);

it('reports a helper that adds the apostrophe and writes with the default escape', function (): void {
    expect(csvNeutraliserFindings(<<<'PHP'
        function acme_write( $out, $v ) {
            fputcsv( $out, array( preg_replace( '/^([=+\-@])/', "'$1", $v ) ) );
        }
        function acme_export( $out ) {
            acme_write( $out, $_GET['n'] );
        }
        PHP))->toBe(['csv@3']);
});
