<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Matcher;

// A PHP function the catalogue did not list returned clean, whatever it
// returned. explode( ',', $_GET['ids'] ) was clean, and so were array_pop(),
// strstr(), dirname() and hundreds more. Each now behaves by what PHP
// declares it to return.

/**
 * @return list<string> rule@line for each finding
 */
function byTypeFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('carries request data through a PHP function that returns text', function (string $call): void {
    expect(byTypeFindings(<<<PHP
        function acme_run() {
            echo {$call};
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
})->with([
    'explode' => ["explode( ',', \$_GET['ids'] )[0]"],
    'array_pop' => ["array_pop( \$_POST['parts'] )"],
    'strstr' => ["strstr( \$_GET['q'], '@' )"],
    'dirname' => ["dirname( \$_GET['path'] )"],
    'max' => ["max( 1, \$_GET['n'] )"],
    'chr' => ["chr( \$_GET['code'] )"],
]);

it('keeps a PHP function that returns only a number or a flag clean', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run() {
            echo strpos( $_GET['q'], 'x' );
            echo substr_count( $_GET['q'], 'x' );
        }
        PHP))->toBe([]);
});

it('does not carry an argument declared as a number', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run() {
            echo chunk_split( 'fixed text', $_GET['n'] );
            echo chunk_split( $_GET['s'], 4 );
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('counts every argument of a call written with names', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run() {
            echo chunk_split( length: $_GET['n'], string: 'fixed text' );
        }
        PHP))->toBe(['wp.xss.unescaped-output@3']);
});

it('keeps a result the arguments cannot shape clean', function (string $call): void {
    expect(byTypeFindings(<<<PHP
        function acme_run( \$object ) {
            echo {$call};
        }
        PHP))->toBe([]);
})->with([
    'a digest' => ["hash_hmac( 'sha256', \$_GET['v'], 'key' )"],
    'a class name' => ["get_class( \$_GET['o'] )"],
    'a type name' => ["gettype( \$_GET['v'] )"],
    'a constant' => ["constant( \$_GET['name'] )"],
]);

it('works out what an output alphabet clears', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            echo '<a title="' . base64_encode( $_GET['v'] ) . '">';
            echo bin2hex( $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE token = '" . base64_encode( $_GET['v'] ) . "'" );
            $wpdb->query( "DELETE FROM t WHERE id = " . base64_encode( $_GET['v'] ) );
            $wpdb->query( "DELETE FROM t WHERE id = " . bin2hex( $_GET['v'] ) );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@7']);
});

it('reads request headers and response bodies as sources', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_headers() {
            $headers = getallheaders();
            echo $headers['X-Acme'];
        }
        function acme_body( $handle ) {
            echo curl_exec( $handle );
        }
        PHP))->toBe(['wp.xss.unescaped-output@4', 'wp.xss.unescaped-output@7']);
});

it('lets the hand-written catalogue win over the declared type', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run() {
            echo htmlspecialchars( $_GET['v'], ENT_QUOTES );
            echo md5( $_GET['v'] );
        }
        PHP))->toBe([]);
});

it('fills the values xml_parse_into_struct() writes back', function (): void {
    expect(byTypeFindings(<<<'PHP'
        function acme_run( $parser ) {
            xml_parse_into_struct( $parser, $_POST['xml'], $values );
            echo $values[0]['value'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('generates an entry for a function that returns text, and none for one that does not', function (): void {
    $registry = testRegistry();

    expect($registry->internalFunction(Matcher::function('explode'))?->arguments)->toBe([0, 1])
        ->and($registry->internalFunction(Matcher::function('max'))?->argumentsFrom)->toBe(1)
        ->and($registry->internalFunction(Matcher::function('strlen')))->toBeNull()
        ->and($registry->internalFunction(Matcher::function('filter_var')))->toBeNull();
});

it('does not carry a pattern built from a stored setting into what preg_replace() returns', function (): void {
    // WooCommerce trims a price with a pattern built from its decimal
    // separator. The pattern chooses what is replaced; its text is not in
    // the result.
    expect(byTypeFindings(<<<'PHP'
        function acme_trim( $price ) {
            $separator = get_option( 'acme_separator' );
            return preg_replace( '/' . preg_quote( $separator, '/' ) . '0++$/', '', $price );
        }
        function acme_run() {
            echo acme_trim( '1.50' );
            echo preg_replace( '/x/', '', $_GET['subject'] );
            echo preg_replace( '/x/', $_GET['replacement'], 'fixed' );
        }
        PHP))->toBe(['wp.xss.unescaped-output@8', 'wp.xss.unescaped-output@9']);
});
