<?php

declare(strict_types=1);

// `in_array( $x, $list, true )` makes `$x` one of `$list`'s values. A list the
// code built itself settles the value as a literal list does, as long as the
// list carries no taint. A loose check settles it only against strings that
// are not numeric, and a check of `strtolower( $x )` settles `$x` up to the
// case of its letters.

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

it('settles a tag a loose check finds in a class constant of tag names', function (): void {
    // Elementor's Utils::validate_html_tag() returns the tag only when its
    // lowered form is on the class's own allowlist, and 'div' otherwise.
    expect(membershipGuardFindings(<<<'PHP'
        namespace Acme\Core;
        class Tags {
            const ALLOWED = array( 'div', 'p', 'h1' );
            const MIXED = array( 'div', '1' );
            const WITH_EMPTY = array( 'div', '' );
            public static function validate( $tag ) {
                return $tag && in_array( strtolower( $tag ), self::ALLOWED ) ? $tag : 'div';
            }
            public static function named( $tag ) {
                return in_array( $tag, Tags::ALLOWED ) ? $tag : 'div';
            }
            public static function inline( $tag ) {
                return in_array( strtoupper( $tag ), array( 'DIV', 'P' ), true ) ? $tag : 'div';
            }
            public static function late( $tag ) {
                return in_array( $tag, static::ALLOWED ) ? $tag : 'div';
            }
            public static function numeric( $tag ) {
                return in_array( $tag, self::MIXED ) ? $tag : 'div';
            }
            public static function empty_string( $tag ) {
                return in_array( $tag, self::WITH_EMPTY ) ? $tag : 'div';
            }
            public static function numbers( $tag ) {
                return in_array( $tag, array( 1, 2 ) ) ? $tag : 'div';
            }
        }
        echo Tags::validate( $_GET['a'] );
        echo Tags::named( $_GET['b'] );
        echo Tags::inline( $_GET['c'] );
        echo Tags::late( $_GET['d'] );
        echo Tags::numeric( $_GET['e'] );
        echo Tags::empty_string( $_GET['f'] );
        echo Tags::numbers( $_GET['g'] );
        PHP))->toBe([
        'wp.xss.unescaped-output@32',
        'wp.xss.unescaped-output@33',
        'wp.xss.unescaped-output@34',
        'wp.xss.unescaped-output@35',
    ]);
});

it('settles only the value whose case the check changed', function (): void {
    expect(membershipGuardFindings(<<<'PHP'
        function acme_tag( $tag ) {
            return in_array( strtolower( $tag ), array( 'div', 'p' ), true ) ? $tag : 'div';
        }
        function acme_trimmed( $tag ) {
            return in_array( trim( $tag ), array( 'div', 'p' ), true ) ? $tag : 'div';
        }
        function acme_other( $a, $b ) {
            return in_array( strtolower( $a ), array( 'div', 'p' ), true ) ? $b : 'div';
        }
        function acme_requested( $tag ) {
            $allowed = explode( ',', $_GET['allowed'] );
            return in_array( strtolower( $tag ), $allowed, true ) ? $tag : 'div';
        }
        echo acme_tag( $_GET['a'] );
        echo acme_trimmed( $_GET['b'] );
        echo acme_other( $_GET['c'], $_GET['d'] );
        echo acme_requested( $_GET['e'] );
        PHP))->toBe([
        'wp.xss.unescaped-output@16',
        'wp.xss.unescaped-output@17',
        'wp.xss.unescaped-output@18',
    ]);
});

it('keeps a name a case-changed check lets through a name', function (): void {
    // `DIV` passes a check of strtolower( $x ) against 'div', and may name a
    // different option than 'div' does.
    expect(membershipGuardFindings(<<<'PHP'
        function acme_save() {
            $name = sanitize_text_field( wp_unslash( $_POST['name'] ) );
            if ( in_array( strtolower( $name ), array( 'colour', 'size' ), true ) ) {
                update_option( $name, 'on' );
            }
            if ( in_array( $name, array( 'colour', 'size' ), true ) ) {
                update_option( $name, 'on' );
            }
        }
        PHP))->toBe(['wp.authz.arbitrary-option-write@5']);
});
