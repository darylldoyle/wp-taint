<?php

declare(strict_types=1);

// A class constant holds one value, known when the class is compiled. The
// value resolver read global constants and not these, so a `switch` on
// `Acme_Notices::DISMISS` credited nothing and a quote kept in `self::Q`
// was unknown text. And the constant table recorded a class constant as a
// global under its bare name.

/**
 * @return list<string> rule@line for each finding
 */
function classConstantFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('settles a value a switch case on a class constant admits', function (): void {
    expect(classConstantFindings(<<<'PHP'
        namespace Acme\Admin;

        class Notices {
            const DISMISS_A = 'acme_notice_a';
            const DISMISS_B = 'acme_notice_b';
            const DISMISS_C = self::DISMISS_A . '_old';

            public static function dismiss() {
                $notice = sanitize_text_field( $_POST['notice'] );
                switch ( $notice ) {
                    case Notices::DISMISS_A:
                    case self::DISMISS_B:
                    case self::DISMISS_C:
                        delete_option( $notice );
                        break;
                }
            }
        }
        PHP))->toBe([]);
});

it('does not settle a value against a class constant a loose comparison can stretch', function (): void {
    expect(classConstantFindings(<<<'PHP'
        class Acme_Notices {
            const NUMBER = '1';
            const FLAG = true;

            public static function dismiss() {
                $notice = sanitize_text_field( $_POST['notice'] );
                switch ( $notice ) {
                    case self::NUMBER:
                        delete_option( $notice );
                        break;
                    case self::FLAG:
                        delete_option( $notice );
                        break;
                    case static::NUMBER:
                        delete_option( $notice );
                        break;
                }
            }
        }
        PHP))->toBe([
        'wp.authz.arbitrary-option-write@10',
        'wp.authz.arbitrary-option-write@13',
        'wp.authz.arbitrary-option-write@16',
    ]);
});

it('reads a class constant as the text it holds, under its class only', function (): void {
    expect(classConstantFindings(<<<'PHP'
        class Acme_Sql {
            const Q = "'";
        }
        function acme_run() {
            global $wpdb;
            $v = esc_sql( $_GET['v'] );
            $wpdb->query( 'SELECT * FROM t WHERE a = ' . Acme_Sql::Q . $v . Acme_Sql::Q );
            $wpdb->query( 'SELECT * FROM t WHERE a = ' . Q . $v . Q );
        }
        PHP))->toBe(['wp.sqli.unprepared-query@9']);
});
