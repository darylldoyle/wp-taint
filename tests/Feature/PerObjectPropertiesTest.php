<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A property write reaches the objects it was made on, not every object of
// the class. WooCommerce's report stores share one query class, and a LIMIT
// one store builds from an option leaked into every other store's queries.

/**
 * @return list<string> rule@line for each SQL finding
 */
function perObjectFindings(string $body): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . $body)),
        static fn (string $finding): bool => str_starts_with($finding, 'wp.sqli.wpdb-query@'),
    ));
}

/** A query class that keeps its clauses in one property. */
function perObjectQuery(): string
{
    return <<<'PHP'
        class Acme_Query {
            private $clauses = array( 'select' => array(), 'limit' => array() );
            public function add( $type, $clause ) {
                $this->clauses[ $type ][] = $clause;
            }
            public function statement() {
                $limit = implode( ' ', $this->clauses['limit'] );
                return 'SELECT ' . implode( ', ', $this->clauses['select'] ) . ' FROM t ' . $limit;
            }
        }
        PHP;
}

it('keeps a write through one subclass away from a sibling subclass', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Reader extends Acme_Query {
            public function run() {
                global $wpdb;
                $this->add( 'select', 'id' );
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Writer extends Acme_Query {
            public function limit() {
                $this->add( 'limit', 'LIMIT ' . $_GET['n'] );
            }
        }
        PHP))->toBe([]);
});

it('keeps a write to one new object away from another', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        function acme_report() {
            global $wpdb;
            $limited = new Acme_Query();
            $limited->add( 'limit', 'LIMIT ' . $_GET['n'] );
            $plain = new Acme_Query();
            $plain->add( 'select', 'id' );
            $wpdb->get_results( $plain->statement() );
            $wpdb->get_results( $limited->statement() );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@19']);
});

it('keeps a protected helper\'s write on the subclass that calls it', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Store extends Acme_Query {
            protected function add_limit() {
                $this->add( 'limit', 'LIMIT ' . $_GET['n'] );
            }
        }
        class Acme_Stats_Store extends Acme_Store {
            public function run() {
                global $wpdb;
                $this->add_limit();
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Categories_Store extends Acme_Store {
            public function run() {
                global $wpdb;
                return $wpdb->get_results( $this->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@21']);
});

it('reads a method\'s own objects, not a subclass that overrides it', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Store extends Acme_Query {
            public function get_data() {
                global $wpdb;
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Stats_Store extends Acme_Store {
            public function get_data() {
                global $wpdb;
                $this->add( 'limit', 'LIMIT ' . $_GET['n'] );
                return $wpdb->get_results( $this->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@22']);
});

it('keeps the objects two classes hold in a property of one name apart', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Stats {
            private $sub;
            public function __construct() {
                $this->sub = new Acme_Query();
            }
            public function run() {
                global $wpdb;
                $this->sub->add( 'limit', 'LIMIT ' . $_GET['n'] );
                return $wpdb->get_results( $this->sub->statement() );
            }
        }
        class Acme_Categories {
            private $sub;
            public function __construct() {
                $this->sub = new Acme_Query();
            }
            public function run() {
                global $wpdb;
                $this->sub->add( 'select', 'id' );
                return $wpdb->get_results( $this->sub->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@20']);
});

it('still reports an object a function it was handed writes', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        function acme_limit( Acme_Query $query ) {
            $query->add( 'limit', 'LIMIT ' . $_GET['n'] );
        }
        function acme_report() {
            global $wpdb;
            $query = new Acme_Query();
            acme_limit( $query );
            $wpdb->get_results( $query->statement() );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@19']);
});

it('still reports a public method of the class that anything may call first', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Store extends Acme_Query {
            public function limit() {
                $this->add( 'limit', 'LIMIT ' . $_GET['n'] );
            }
            public function run() {
                global $wpdb;
                return $wpdb->get_results( $this->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@18']);
});

// A write a summary records to `$this` lands on the object the call runs on.
// Nothing calls these writers, so nothing reaches the reader's object.

it('keeps a write in a subclass nothing calls off another subclass\'s object', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Reader extends Acme_Query {
            public function run() {
                global $wpdb;
                $this->add( 'select', 'id' );
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Writer extends Acme_Query {
            public function never_called() {
                $this->add( 'limit', 'LIMIT ' . get_option( 'posts_per_page' ) );
            }
        }
        PHP))->toBe([]);
});

it('keeps a write to a new object off a subclass\'s object', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Reader extends Acme_Query {
            public function run() {
                global $wpdb;
                $this->add( 'select', 'id' );
                return $wpdb->get_results( $this->statement() );
            }
        }
        function acme_never_called() {
            $query = new Acme_Query();
            $query->add( 'limit', 'LIMIT ' . get_option( 'posts_per_page' ) );
        }
        PHP))->toBe([]);
});

it('keeps a subclass method\'s write off an object of the base class', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Stats_Store extends Acme_Query {
            public function add_limit() {
                $this->add( 'limit', 'LIMIT ' . $_GET['per_page'] );
            }
        }
        function acme_plain_report() {
            global $wpdb;
            $query = new Acme_Query();
            $query->add( 'select', 'id' );
            $wpdb->get_results( $query->statement() );
        }
        PHP))->toBe([]);
});

// One summary serves every object it answers for. A method that reads a
// property the objects hold apart still runs once for each of them.

it('shares a summary across objects that read the same, and still reports each flow', function (): void {
    expect(perObjectFindings(<<<'PHP'
        class Acme_Store {
            protected $where = '1=1';
            public function where( $clause ) {
                $this->where = $clause;
            }
            public function sql() {
                return 'SELECT * FROM t WHERE ' . $this->where;
            }
        }
        class Acme_Orders extends Acme_Store {
            public function run() {
                global $wpdb;
                $this->where( $_GET['field'] );
                return $wpdb->get_results( $this->sql() );
            }
        }
        class Acme_Coupons extends Acme_Store {
            public function run() {
                global $wpdb;
                $this->where( 'id = 1' );
                return $wpdb->get_results( $this->sql() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@15']);
});

it('runs a method again on an object whose property holds something else', function (): void {
    expect(perObjectFindings(<<<'PHP'
        class Acme_Store {
            protected $table = 'posts';
            public function count() {
                global $wpdb;
                return $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $this->table );
            }
        }
        class Acme_Orders extends Acme_Store {
            public function __construct() {
                $this->table = $_GET['table'];
            }
        }
        class Acme_Coupons extends Acme_Store {
        }
        function acme_counts() {
            $orders = new Acme_Orders();
            $coupons = new Acme_Coupons();
            return array( $orders->count(), $coupons->count() );
        }
        PHP))->toBe(['wp.sqli.wpdb-query@6']);
});

it('keeps a held-back helper\'s own write on the subclass that calls it', function (): void {
    expect(perObjectFindings(<<<'PHP'
        class Acme_Store {
            protected $limit = '';
            protected function add_limit() {
                $this->limit = 'LIMIT ' . $_GET['n'];
            }
            protected function statement() {
                return 'SELECT * FROM t ' . $this->limit;
            }
        }
        class Acme_Stats_Store extends Acme_Store {
            public function run() {
                global $wpdb;
                $this->add_limit();
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Categories_Store extends Acme_Store {
            public function run() {
                global $wpdb;
                return $wpdb->get_results( $this->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@15']);
});

// A method's own run holds back its writes to `$this` only when every call
// to it runs it on the caller's object. A call through a callable runs the
// method's own summary, which cannot carry a write the body makes itself.

/**
 * @return list<string> rule@line for each finding of one rule
 */
function perObjectRule(string $rule, string $body): array
{
    return array_values(array_filter(
        findingSignatures(scanCode("<?php\n" . $body)),
        static fn (string $finding): bool => str_starts_with($finding, $rule . '@'),
    ));
}

/** A base class whose protected `load_term()` only a subclass calls, with `$call` making the call. */
function perObjectHeldBack(string $call): string
{
    return <<<PHP
        abstract class Acme_Base {
            protected \$term = '';
            protected function load_term() {
                \$this->term = wp_unslash( \$_GET['term'] );
            }
        }
        class Acme_Search extends Acme_Base {
            public \$keys = array( 'a' );
            public function __construct() {
                add_action( 'wp', array( \$this, 'init' ) );
                add_action( 'wp_footer', array( \$this, 'query' ) );
            }
            public function init() {
        {$call}
            }
            public function query() {
                global \$wpdb;
                \$wpdb->get_results( "SELECT * FROM {\$wpdb->posts} WHERE post_title = '" . \$this->term . "'" );
            }
        }
        new Acme_Search();
        PHP;
}

it('lands the write of a protected method a subclass calls through a callable', function (string $call): void {
    expect(perObjectFindings(perObjectHeldBack($call)))->toBe(['wp.sqli.wpdb-query@19']);
})->with([
    'a copy of $this' => ["\$self = \$this; \$self->load_term();"],
    'a callable variable' => ["\$cb = array( \$this, 'load_term' ); \$cb();"],
    'array_walk()' => ["array_walk( \$this->keys, array( \$this, 'load_term' ) );"],
]);

it('lands the write of a protected method a subclass calls on an object it was handed', function (): void {
    expect(perObjectFindings(<<<'PHP'
        abstract class Acme_Base {
            protected $term = '';
            protected function load_term() {
                $this->term = wp_unslash( $_GET['term'] );
            }
        }
        class Acme_Search extends Acme_Base {
            public function load_from( Acme_Base $other ) {
                $other->load_term();
            }
            public function query() {
                global $wpdb;
                $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $this->term . "'" );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@14']);
});

it('lands a held-back method\'s write to an object a property holds', function (): void {
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        class Acme_Report {
            protected $sub;
            public function __construct() {
                $this->sub = new Acme_Query();
            }
            protected function add_limit() {
                $this->sub->add( 'limit', 'LIMIT ' . $_GET['n'] );
            }
            public function run() {
                global $wpdb;
                return $wpdb->get_results( $this->sub->statement() );
            }
        }
        class Acme_Stats_Report extends Acme_Report {
            public function limited() {
                $this->add_limit();
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@22']);
});

it('keeps a held-back method\'s write to a property\'s object on the subclass that calls it', function (): void {
    // The base class's own run cannot tell which object `$this->sub` holds,
    // so a write it made would reach every Acme_Query.
    expect(perObjectFindings(perObjectQuery() . "\n" . <<<'PHP'
        abstract class Acme_Report {
            protected $sub;
            protected function add_limit() {
                $this->sub->add( 'limit', 'LIMIT ' . $_GET['n'] );
            }
        }
        class Acme_Stats_Report extends Acme_Report {
            public function __construct() {
                $this->sub = new Acme_Query();
            }
            public function limited() {
                global $wpdb;
                $this->add_limit();
                return $wpdb->get_results( $this->sub->statement() );
            }
        }
        class Acme_Plain_Report extends Acme_Report {
            public function __construct() {
                $this->sub = new Acme_Query();
            }
            public function run() {
                global $wpdb;
                return $wpdb->get_results( $this->sub->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@25']);
});

it('lands the write of a protected method a subclass calls through call_user_func()', function (): void {
    expect(perObjectRule('wp.xss.unescaped-output', <<<'PHP'
        abstract class Acme_Base {
            protected $term = '';
            protected function load_term() {
                $this->term = wp_unslash( $_GET['term'] );
            }
        }
        class Acme_Search extends Acme_Base {
            public function __construct() {
                add_action( 'wp', array( $this, 'init' ) );
                add_action( 'wp_footer', array( $this, 'query' ) );
            }
            public function init() {
                call_user_func( array( $this, 'load_term' ) );
            }
            public function query() {
                echo '<p>' . $this->term . '</p>';
            }
        }
        new Acme_Search();
        PHP))->toBe(['wp.xss.unescaped-output@17']);
});

it('lands the write of a protected method a subclass calls through array_map()', function (): void {
    expect(perObjectRule('wp.xss.unescaped-output', <<<'PHP'
        abstract class Acme_Base {
            protected $values = array();
            protected function read_field( $k ) {
                $this->values[ $k ] = $_POST[ $k ];
            }
            public function show() {
                foreach ( $this->values as $v ) {
                    echo '<td>' . $v . '</td>';
                }
            }
        }
        class Acme_Form extends Acme_Base {
            public function save() {
                array_map( array( $this, 'read_field' ), array( 'title', 'body' ) );
            }
        }
        function acme_form() {
            $f = new Acme_Form();
            $f->save();
            $f->show();
        }
        add_action( 'admin_init', 'acme_form' );
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('lands an option a held-back method writes', function (): void {
    // Stored data carries no `url`, so only the write makes the redirect a
    // finding.
    expect(perObjectRule('wp.redirect.open-redirect', <<<'PHP'
        abstract class Acme_Base {
            protected function save_target() {
                update_option( 'acme_target', $_GET['target'] );
            }
        }
        class Acme_Settings extends Acme_Base {
            public function save() {
                $this->save_target();
            }
        }
        function acme_go() {
            wp_redirect( get_option( 'acme_target' ) );
            exit;
        }
        PHP))->toBe(['wp.redirect.open-redirect@13']);
});

// The ways a method can reach its own object other than `$this->name`. A
// copy of `$this` reaches the object the call runs on, so a call on another
// object runs the method there. The others do not read the property map
// through the receiver, so they give the same answer on every object.

/** A query whose `sql()` reads the limit through `$body`, called on two objects. */
function perObjectReach(string $body, string $after = ''): string
{
    return <<<PHP
        class Acme_Query {
            public \$limit = '';
            public function set( \$limit ) {
                \$this->limit = \$limit;
            }
            public function sql() {
        {$body}
            }
        }
        function acme_report() {
            global \$wpdb;
            \$tainted = new Acme_Query();
            \$tainted->set( 'LIMIT ' . \$_GET['n'] );
            \$plain = new Acme_Query();
            \$wpdb->query( \$plain->sql() );
            \$wpdb->query( \$tainted->sql() );
        }
        {$after}
        PHP;
}

it('runs a method that copies $this on the object the call names', function (): void {
    expect(perObjectFindings(perObjectReach(<<<'PHP'
                $that = $this;
                return 'SELECT * FROM t ' . $that->limit;
        PHP)))->toBe(['wp.sqli.wpdb-query@18']);
});

it('runs a method that calls another through a copy of $this on the object the call names', function (): void {
    expect(perObjectFindings(perObjectReach(<<<'PHP'
                $that = $this;
                return 'SELECT * FROM t ' . $that->limit_clause();
            }
            public function limit_clause() {
                return $this->limit;
        PHP)))->toBe(['wp.sqli.wpdb-query@21']);
});

it('reads the whole class through an object handed to a function', function (): void {
    expect(perObjectFindings(perObjectReach(<<<'PHP'
                return 'SELECT * FROM t ' . acme_limit_of( $this );
        PHP, <<<'PHP'
        function acme_limit_of( Acme_Query $query ) {
            return $query->limit;
        }
        PHP)))->toBe(['wp.sqli.wpdb-query@16', 'wp.sqli.wpdb-query@17']);
});

it('reads no property through get_object_vars(), a cast, a loop or a closure', function (string $body): void {
    expect(perObjectFindings(perObjectReach($body)))->toBe([]);
})->with([
    'get_object_vars' => [<<<'PHP'
                $vars = get_object_vars( $this );
                return 'SELECT * FROM t ' . $vars['limit'];
        PHP],
    'a cast' => [<<<'PHP'
                $vars = (array) $this;
                return 'SELECT * FROM t ' . $vars['limit'];
        PHP],
    'a loop' => [<<<'PHP'
                $sql = 'SELECT * FROM t ';
                foreach ( $this as $value ) {
                    $sql .= $value;
                }
                return $sql;
        PHP],
    'a closure' => [<<<'PHP'
                $limit = function () {
                    return $this->limit;
                };
                return 'SELECT * FROM t ' . $limit();
        PHP],
]);

// A new allocation site's slot is one more slot a read through the class
// sees, so the read runs again when the first write lands there.

it('lets a read through the class see an allocation site written later', function (): void {
    $directory = sys_get_temp_dir() . '/wp-taint-per-object-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/a.php', "<?php\n" . perObjectQuery() . "\n" . <<<'PHP'
        function acme_render( Acme_Query $query ) {
            global $wpdb;
            return $wpdb->get_results( $query->statement() );
        }
        PHP);
    file_put_contents($directory . '/b.php', <<<'PHP'
        <?php
        function acme_limited() {
            $query = new Acme_Query();
            $query->add( 'limit', 'LIMIT ' . $_GET['n'] );
            return $query;
        }
        PHP);

    $scan = static fn (bool $incremental): array => findingSignatures((new Scanner(
        testRegistry(),
        new AnalysisOptions(incrementalRounds: $incremental),
        $directory,
    ))->scan((new FileFinder())->find([$directory])));

    try {
        $full = $scan(false);
        $incremental = $scan(true);
    } finally {
        array_map('unlink', glob($directory . '/*.php') ?: []);
        rmdir($directory);
    }

    expect($incremental)->toBe($full)->toBe(['wp.sqli.wpdb-query@14']);
});

// Literal variants and receiver variants have a cap each. Sixteen literal
// variants used to stop every receiver variant, so a pending one applied the
// method's own summary, and its write reached the whole class.

it('keeps the receiver variants going past the literal cap', function (): void {
    $keys = '';

    for ($i = 0; $i < 17; $i++) {
        $keys .= "\$query->add( 'key{$i}', 'x' );\n";
    }

    expect(perObjectFindings(perObjectQuery() . "\n" . <<<PHP
        function acme_many_keys( \$query ) {
        {$keys}
        }
        class Acme_Reader extends Acme_Query {
            public function run() {
                global \$wpdb;
                \$this->add( 'select', 'id' );
                return \$wpdb->get_results( \$this->statement() );
            }
        }
        class Acme_Writer extends Acme_Query {
            public function limit() {
                \$this->add( 'limit', 'LIMIT ' . \$_GET['n'] );
            }
        }
        PHP))->toBe([]);
});

// A literal variant a call on `$this` asks for counts against the literal
// cap. Past it the base summary stands in, and the write still lands on the
// object the call runs on.

it('keeps each object\'s write apart past the literal cap', function (): void {
    $stores = '';

    for ($i = 0; $i < 17; $i++) {
        $stores .= "class Acme_Store_{$i} extends Acme_Query {\n"
            . "    public function run() { \$this->add( 'key{$i}', 'x' ); }\n"
            . "}\n";
    }

    expect(perObjectFindings(perObjectQuery() . "\n" . $stores . <<<'PHP'
        class Acme_Reader extends Acme_Query {
            public function run() {
                global $wpdb;
                $this->add( 'select', 'id' );
                return $wpdb->get_results( $this->statement() );
            }
        }
        class Acme_Writer extends Acme_Query {
            public function run() {
                global $wpdb;
                $this->add( 'limit', 'LIMIT ' . $_GET['n'] );
                return $wpdb->get_results( $this->statement() );
            }
        }
        PHP))->toBe(['wp.sqli.wpdb-query@74']);
});
