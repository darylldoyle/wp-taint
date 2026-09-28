<?php

declare(strict_types=1);

// Conventions the catalogue relies on, applied the same way everywhere. The
// core table names are `$wpdb`'s, and a receiver is the database handle when
// the receiver resolver says so: declared types first, then the `$wpdb` and
// `$db` names.

/**
 * @return list<string> rule@line for each finding
 */
function conventionFindings(string $body, string $registry = 'wordpress'): array
{
    return findingSignatures(scanCode("<?php\n" . $body, registry: testRegistry($registry)));
}

it('credits a core table name on the database handle only', function (): void {
    expect(conventionFindings(<<<'PHP'
        class Acme_Report {
            private $options;
            public function __construct( $source ) {
                $this->options = $source->table();
            }
            public function run() {
                global $wpdb;
                $wpdb->get_results( "SELECT * FROM {$wpdb->options}" );
                return $wpdb->get_results( "SELECT * FROM {$this->options}" );
            }
        }
        PHP))->toBe(['wp.sqli.unprepared-query@10']);
});

it('reads $GLOBALS[\'wpdb\'] as the database handle', function (): void {
    // WPS Hide Login's uninstall script optimises the options table this way.
    expect(conventionFindings(<<<'PHP'
        function acme_uninstall() {
            $GLOBALS['wpdb']->query( 'OPTIMIZE TABLE `' . $GLOBALS['wpdb']->prefix . 'options`' );
        }
        PHP))->toBe([]);
});

it('reads a declared type before the $db name in a prepare() format', function (): void {
    expect(conventionFindings(<<<'PHP'
        class Acme_DB {
            public $prefix;
            public function __construct( $prefix ) {
                $this->prefix = $prefix;
            }
        }
        function acme_typed( Acme_DB $db ) {
            global $wpdb;
            return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$db->prefix}items WHERE id = %d", 1 ) );
        }
        function acme_untyped( $db ) {
            global $wpdb;
            return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$db->prefix}items WHERE id = %d", 1 ) );
        }
        PHP))->toBe(['wp.sqli.prepare-non-literal@10']);
});

it('reports a request URL through the VIP request wrapper, which checks no host', function (): void {
    expect(conventionFindings(<<<'PHP'
        function acme_fetch() {
            vip_safe_wp_remote_get( 'https://api.example.com/v1' );
            return vip_safe_wp_remote_get( $_GET['url'] );
        }
        PHP, 'wordpress-vip'))->toBe(['wp.ssrf.remote-request@4']);
});
