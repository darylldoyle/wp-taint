<?php

declare(strict_types=1);

// An array's elements under literal keys are part of the array, and so are its
// keys. A reference shares all of it, and a key written from request data
// carries that data into every read of the keys.

/**
 * @return list<string> rule@line for each finding
 */
function wholeArrayFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('shares every element through a reference, either way round', function (): void {
    $findings = wholeArrayFindings(<<<'PHP'
        function acme_show() {
            $c = array();
            $d = &$c;
            $d['j'] = $_GET['y'];
            echo $c['j'];
            echo $c['m'];
            $e = array();
            $f = &$e;
            $e['k'] = $_GET['z'];
            echo $f['k'];
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@6')
        ->and($findings)->toContain('wp.xss.unescaped-output@11')
        ->and($findings)->not->toContain('wp.xss.unescaped-output@7');
});

it('carries a computed key\'s taint to the array\'s keys and not its values', function (): void {
    $findings = wholeArrayFindings(<<<'PHP'
        function acme_names() {
            $seen = array();
            foreach ( (array) $_POST['names'] as $name ) {
                $seen[ $name ] = true;
            }
            foreach ( $seen as $key => $flag ) {
                echo $key;
                echo $flag ? 'yes' : 'no';
            }
            echo implode( ',', array_keys( $seen ) );
        }
        PHP);

    expect($findings)->toContain('wp.xss.unescaped-output@8')
        ->and($findings)->toContain('wp.xss.unescaped-output@11')
        ->and($findings)->not->toContain('wp.xss.unescaped-output@9');
});

it('reports a query built from the keys of an array keyed by stored data', function (): void {
    // Complianz's get_supported_languages(): the stored language codes are
    // the keys, and the query is built from array_keys().
    expect(wholeArrayFindings(<<<'PHP'
        function acme_languages() {
            $languages = array( 'en' => 'en' );
            foreach ( (array) get_option( 'acme_languages' ) as $code ) {
                $languages[ $code ] = $code;
            }
            return array_keys( $languages );
        }
        function acme_clear() {
            global $wpdb;
            $languages = acme_languages();
            $wpdb->query( "DELETE FROM t WHERE language NOT IN ('" . implode( "','", $languages ) . "')" );
        }
        PHP))->toContain('wp.sqli.wpdb-query@12');
});

it('keeps a key\'s taint through a copy and a return', function (): void {
    expect(wholeArrayFindings(<<<'PHP'
        function acme_index() {
            $index = array();
            $index[ $_GET['slug'] ] = 1;
            $copy = $index;
            return $copy;
        }
        function acme_list() {
            foreach ( acme_index() as $slug => $n ) {
                echo $slug;
            }
        }
        PHP))->toContain('wp.xss.unescaped-output@10');
});

it('records a key checked against a known list as clean', function (): void {
    // WooCommerce's REST settings controllers: each setting a request names is
    // checked against the ids of their own definitions, stored under its name,
    // and saved in a second loop.
    expect(wholeArrayFindings(<<<'PHP'
        function acme_defaults() {
            return array( 'colour' => 'red', 'size' => 'm' );
        }
        function acme_save_all() {
            $allowed   = array_keys( acme_defaults() );
            $validated = array();
            foreach ( (array) $_POST['settings'] as $name => $value ) {
                if ( ! in_array( $name, $allowed, true ) ) {
                    continue;
                }
                $validated[ $name ] = sanitize_text_field( $value );
            }
            foreach ( $validated as $name => $value ) {
                update_option( $name, $value );
            }
        }
        PHP))->toBe([]);
});
