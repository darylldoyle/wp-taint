<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// A callee that writes its parameter somewhere other than its return: a
// property, a closure's capture, or a file it includes. The caller publishes
// its own argument's taint there, and it used to publish all of it, whatever
// the callee cleared on the way. `$this->v = esc_html( $x )` stored HTML taint
// if the caller passed request data. The summary now records which kinds
// reach each place, and the caller publishes only those.

/**
 * @param array<string, string> $files
 */
function scanSideChannelTree(array $files): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-side-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);

    foreach ($files as $relative => $contents) {
        file_put_contents($directory . '/' . $relative, $contents);
    }

    try {
        return (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        foreach (array_keys($files) as $relative) {
            unlink($directory . '/' . $relative);
        }

        rmdir($directory);
    }
}

/**
 * @return list<string> rule@file:line for each finding
 */
function sideChannelFindings(ScanResult $result): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->file . ':' . $finding->line,
        $result->findings->all(),
    );
}

it('stores only what survives the callee in a property', function (): void {
    $findings = sideChannelFindings(scanSideChannelTree([
        'plugin.php' => <<<'PHP'
            <?php
            class Acme_Box {
                public $v;
                public function put( $x ) {
                    $this->v = esc_html( $x );
                }
            }
            function acme_render() {
                global $wpdb;
                $box = new Acme_Box();
                $box->put( $_GET['x'] );
                echo $box->v;
                $wpdb->query( "DELETE FROM t WHERE v = '{$box->v}'" );
            }
            PHP,
    ]));

    expect($findings)->not->toContain('wp.xss.unescaped-output@plugin.php:12')
        ->and($findings)->toContain('wp.sqli.wpdb-query@plugin.php:13');
});

it('hands an included file only what survives the callee', function (): void {
    $findings = sideChannelFindings(scanSideChannelTree([
        'tpl.php' => "<?php\necho \$label;\nunserialize( \$label );\n",
        'plugin.php' => <<<'PHP'
            <?php
            function acme_render_tpl( $x ) {
                $label = esc_html( $x );
                include __DIR__ . '/tpl.php';
            }
            function acme_page() {
                acme_render_tpl( $_GET['x'] );
            }
            PHP,
    ]));

    expect($findings)->not->toContain('wp.xss.unescaped-output@tpl.php:2')
        ->and($findings)->toContain('wp.rce.unserialize@tpl.php:3');
});

it('hands a closure only what survives the callee', function (): void {
    $findings = sideChannelFindings(scanSideChannelTree([
        'plugin.php' => <<<'PHP'
            <?php
            function acme_footer( $x ) {
                $label = esc_html( $x );
                add_action( 'wp_footer', function () use ( $label ) {
                    echo $label;
                    unserialize( $label );
                } );
            }
            function acme_init() {
                acme_footer( $_GET['x'] );
            }
            PHP,
    ]));

    expect($findings)->not->toContain('wp.xss.unescaped-output@plugin.php:5')
        ->and($findings)->toContain('wp.rce.unserialize@plugin.php:6');
});

it('does not hand an included file request kinds that only a stored value carries there', function (): void {
    // The request id only names the option. What reaches the included file is
    // the stored form, so its $settings is stored data, not the request.
    $findings = sideChannelFindings(scanSideChannelTree([
        'entry.php' => "<?php\n\$parsed = unserialize( \$settings['raw'] );\n",
        'plugin.php' => <<<'PHP'
            <?php
            function acme_after_submit( $form ) {
                $settings = $form['settings'];
                include __DIR__ . '/entry.php';
            }
            function acme_load_form( $id ) {
                $form = get_option( 'acme_form_' . absint( $id ) );
                acme_after_submit( $form );
            }
            function acme_submit() {
                acme_load_form( $_GET['id'] );
            }
            PHP,
    ]));

    expect($findings)->toContain('wp.rce.unserialize-stored@entry.php:2')
        ->and($findings)->not->toContain('wp.rce.unserialize@entry.php:2');
});

it('keeps an escaped value\'s history through a setter that stores it as it came', function (): void {
    // The probe run's seed leaves out the escaping markers, so they ride with
    // the HTML kind they qualify rather than with what the probe recorded.
    $findings = sideChannelFindings(scanSideChannelTree([
        'plugin.php' => <<<'PHP'
            <?php
            class Acme_Title {
                public $t;
                public function set( $x ) {
                    $this->t = $x;
                }
            }
            function acme_title() {
                $v = apply_filters( 'acme_title', esc_html( $_GET['x'] ) );
                $o = new Acme_Title();
                $o->set( $v );
                echo $o->t;
            }
            PHP,
    ]));

    expect($findings)->toContain('wp.xss.escape-voided@plugin.php:12');
});

it('keeps a value of unknown origin unknown through a setter that stores it as it came', function (): void {
    $findings = sideChannelFindings(scanSideChannelTree([
        'plugin.php' => <<<'PHP'
            <?php
            class Acme_Note {
                public $n;
                public function set( $x ) {
                    $this->n = $x;
                }
            }
            add_filter( 'the_title', 'acme_note_title' );
            function acme_note_title( $title ) {
                $o = new Acme_Note();
                $o->set( $title );
                echo $o->n;
                return $title;
            }
            PHP,
    ]));

    expect($findings)->toContain('wp.output.unescaped-unknown@plugin.php:12');
});
