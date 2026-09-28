<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\CharacterProof;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

// What a value can carry follows from the characters it can contain, kind by
// kind. The guard used one set for every kind, so rejecting `<` and `>`
// cleared SQL as well, and letters and spaces cleared SQL outside quotes,
// where `1 OR 1` needs nothing more.

/**
 * @return list<string> rule@line for each finding
 */
function proofFindings(string $body): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->line,
        scanCode("<?php\n" . $body)->findings->all(),
    );
}

it('clears every payload for digits, and SQL outright', function (): void {
    $proof = CharacterProof::ofCharacters('0123456789');

    expect($proof->clearsEveryPayload())->toBeTrue()
        ->and($proof->settles(TaintKind::Sql))->toBeTrue()
        ->and($proof->clears->has(TaintKind::Identifier))->toBeFalse()
        ->and($proof->clears->has(TaintKind::ObjectId))->toBeFalse();
});

it('clears SQL inside quotes only for a value that can hold a space or a dash', function (string $characters): void {
    $proof = CharacterProof::ofCharacters($characters);

    expect($proof->clears->has(TaintKind::Sql))->toBeTrue()
        ->and($proof->sqlQuotedOnly)->toBeTrue()
        ->and($proof->apply(TaintSet::of(TaintKind::Sql))->has(TaintKind::SqlUnquoted))->toBeTrue();
})->with([
    'space' => ['abc 123'],
    'dash' => ['abc-'],
    'operator' => ['a=1'],
]);

it('keeps SQL for a value that can hold a quote or a backslash', function (string $characters): void {
    expect(CharacterProof::ofCharacters($characters)->clears->has(TaintKind::Sql))->toBeFalse();
})->with([
    'single quote' => ["a'"],
    'double quote' => ['a"'],
    'backslash' => ['a\\'],
    'backtick' => ['a`'],
]);

it('proves only what a denylist excludes', function (): void {
    $angles = CharacterProof::ofAllExcept('<>');
    $fastPath = CharacterProof::ofAllExcept('<>"\'');

    expect($angles->clears->isEmpty())->toBeTrue()
        ->and($fastPath->clears->has(TaintKind::Html))->toBeTrue()
        ->and($fastPath->clears->has(TaintKind::HtmlAttr))->toBeTrue()
        ->and($fastPath->clears->has(TaintKind::Sql))->toBeFalse();
});

it('refuses a pattern whose modifiers change what the class means', function (string $pattern, bool $read): void {
    expect(CharacterProof::pattern($pattern) !== null)->toBe($read);
})->with([
    'none' => ['/^[a-z]+$/', true],
    'caseless and unicode' => ['/^[a-z]+$/iu', true],
    'multiline' => ['/^[a-z]+$/m', false],
    'extended' => ['/^[a-z]+$/x', false],
]);

it('reports a value a denylist of angle brackets let through, outside HTML', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = $_GET['v'];
            if ( ! preg_match( '/[<>]/', $v ) ) {
                $wpdb->query( "DELETE FROM t WHERE id = $v" );
                echo "<script>var t = '" . $v . "';</script>";
            }
        }
        PHP))->toContain('wp.sqli.wpdb-query@6')->toContain('wp.xss.unescaped-output@7');
});

it('does not credit an anchored allowlist that matches one line', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            $v = $_GET['v'];
            if ( preg_match( '/^[a-z]+$/m', $v ) ) {
                echo $v;
            }
        }
        PHP))->toContain('wp.xss.unescaped-output@5');
});

it('credits letters, digits and spaces inside quotes only', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_guarded() {
            global $wpdb;
            $v = $_GET['v'];
            if ( preg_match( '/^[a-z0-9 ]+$/i', $v ) ) {
                $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
                $wpdb->query( "DELETE FROM t WHERE id = $v" );
                echo $v;
            }
        }
        function acme_stripped() {
            global $wpdb;
            $v = preg_replace( '/[^a-zA-Z0-9 ]/', '', $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE name = '$v'" );
            $wpdb->query( "DELETE FROM t WHERE id = $v" );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@7', 'wp.sqli.unprepared-query@15']);
});

it('clears a value a digit check or a number check admits, quoted or not', function (string $check): void {
    expect(proofFindings(<<<PHP
        function acme_run() {
            global \$wpdb;
            \$v = \$_GET['v'];
            if ( {$check}( \$v ) ) {
                \$wpdb->query( "DELETE FROM t WHERE id = \$v" );
            }
        }
        PHP))->toBe([]);
})->with(['ctype_digit', 'is_numeric']);

it('still reports a name a character check admits as an option name', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            $name = $_POST['option'];
            if ( ctype_alpha( $name ) ) {
                update_option( $name, 1 );
            }
        }
        PHP))->toContain('wp.authz.arbitrary-option-write@5');
});

it('clears a name a fixed list admits', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            $name = $_POST['option'];
            if ( in_array( $name, array( 'acme_colour', 'acme_size' ), true ) ) {
                update_option( $name, 1 );
            }
        }
        PHP))->toBe([]);
});

it('clears HTML for a value with no angle bracket and no quote, ampersand or not', function (): void {
    // A character reference in text or in a quoted attribute is a character,
    // and esc_html() passes an existing one through.
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            foreach ( (array) $_POST['users'] as $user ) {
                if ( preg_match( '/[\<\>\"\']/', $user ) ) {
                    continue;
                }
                echo '<input type="text" value="' . $user . '" />';
            }
        }
        PHP))->toBe([]);
});

it('does not report digits written to an option as untrusted', function (): void {
    $findings = scanCode(<<<'PHP'
        <?php
        function acme_run() {
            $id = wp_unslash( $_GET['id'] ?? '' );
            if ( ! ctype_digit( $id ) ) {
                return;
            }
            update_option( 'acme_id', $id );
        }
        function acme_raw() {
            update_option( 'acme_raw', wp_unslash( $_GET['raw'] ?? '' ) );
        }
        PHP, null, testRegistry(storedWrites: true))->findings->all();

    expect(array_map(static fn ($f): string => $f->ruleId . '@' . $f->line, $findings))
        ->toBe(['wp.stored.untrusted-write@10']);
});

it('settles a marker a digit check leaves nothing for', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_unknown( $v ) {
            if ( ctype_digit( $v ) ) {
                echo $v;
            }
        }
        function acme_voided() {
            $v = apply_filters( 'acme_v', esc_html( $_GET['v'] ) );
            if ( ctype_digit( $v ) ) {
                echo $v;
            }
        }
        function acme_unguarded( $v ) {
            echo $v;
        }
        PHP))->toBe(['wp.output.unescaped-unknown@14']);
});

it('credits a run of classes and characters anchored at both ends', function (): void {
    // Contact Form 7 checks an attribute name this way before printing it.
    expect(proofFindings(<<<'PHP'
        function acme_attribute() {
            $name = $_GET['name'];
            if ( preg_match( '/^[a-z_:][a-z_:.0-9-]*$/', $name ) ) {
                echo $name;
            }
        }
        function acme_prefixed() {
            $slug = $_GET['slug'];
            if ( preg_match( '/^acme-\d{1,4}$/', $slug ) ) {
                echo $slug;
            }
        }
        function acme_loop() {
            foreach ( (array) $_GET['atts'] as $name => $value ) {
                if ( ! preg_match( '/^[a-z_:][a-z_:.0-9-]*$/', $name ) ) {
                    continue;
                }
                echo $name;
            }
        }
        PHP))->toBe([]);
});

it('does not credit a run that admits more than it names', function (string $pattern): void {
    expect(proofFindings(<<<PHP
        function acme_run() {
            \$v = \$_GET['v'];
            if ( preg_match( '{$pattern}', \$v ) ) {
                echo \$v;
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@5']);
})->with([
    'any character' => ['/^[a-z].+$/'],
    'alternation' => ['/^[a-z]+|<b>$/'],
    'group' => ['/^([a-z]+)$/'],
    'negated class beside another' => ['/^[a-z][^0-9]*$/'],
    'one end only' => ['/^[a-z][a-z0-9]*/'],
    'escaped end' => ['/^[a-z]+\\$/'],
    'letter escape' => ['/^[a-z]\\S+$/'],
]);

it('still reads a negated class on its own as everything but its characters', function (): void {
    expect(proofFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = $_GET['v'];
            if ( preg_match( '/^[^<>"\'&]+$/', $v ) ) {
                echo $v;
                $wpdb->query( "DELETE FROM t WHERE id = $v" );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@7']);
});
