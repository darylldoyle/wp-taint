<?php

declare(strict_types=1);

// `__construct( private string $name )` declares a property and assigns it.
// php-cfg read the parameter and dropped the property, so nothing wrote
// `$this->name`, and a value handed to the constructor never reached the
// methods that read it.

/**
 * @return list<string> rule@line for each finding
 */
function promotedPropertyFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('carries a value handed to a promoted parameter into the property', function (string $modifiers): void {
    expect(promotedPropertyFindings(<<<PHP
        class Acme_Greeting {
            public function __construct( {$modifiers} string \$name, private int \$count = 0 ) {
            }
            public function render() {
                echo '<p>' . \$this->name . '</p>';
                echo \$this->count;
            }
        }
        function acme_run() {
            ( new Acme_Greeting( \$_GET['n'], 3 ) )->render();
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
})->with([
    'private' => ['private'],
    'readonly' => ['public readonly'],
]);

it('lets the constructor body read what the promotion assigned', function (): void {
    expect(promotedPropertyFindings(<<<'PHP'
        class Acme_Greeting {
            public function __construct( private string $name ) {
                echo '<p>' . $this->name . '</p>';
            }
        }
        function acme_run() {
            new Acme_Greeting( $_GET['n'] );
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('keeps a promoted property\'s declared type for the receiver it holds', function (): void {
    expect(promotedPropertyFindings(<<<'PHP'
        class Acme_DB {
            public $prefix = 'acme_';
        }
        class Acme_Report {
            public function __construct( private Acme_DB $db ) {
            }
            public function run() {
                global $wpdb;
                $sql = "SELECT * FROM {$this->db->prefix}items WHERE id = %d";
                return $wpdb->get_results( $wpdb->prepare( $sql, 1 ) );
            }
        }
        PHP))->toBe(['wp.sqli.prepare-non-literal@11']);
});
