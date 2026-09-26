<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// Gravity Forms fires its hooks through gf_do_action() and gf_apply_filters():
// a name and its modifiers in an array, each modifier firing a longer name as
// well. A callback on such a hook used to receive nothing from the dispatch,
// which is where the visitor's submission arrives.

function scanModifiedHooks(string $source): ScanResult
{
    $directory = sys_get_temp_dir() . '/wp-taint-gf-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    file_put_contents($directory . '/plugin.php', $source);

    try {
        return (new Scanner(testRegistry(), new AnalysisOptions(), $directory))
            ->scan((new FileFinder())->find([$directory]));
    } finally {
        unlink($directory . '/plugin.php');
        rmdir($directory);
    }
}

/**
 * @return list<string> rule@line for each finding
 */
function modifiedHookFindings(ScanResult $result): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . '@' . $finding->line,
        $result->findings->all(),
    );
}

it('delivers the dispatch arguments to a callback on the base name', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_after_submission', 'acme_after', 10, 2 );
        function acme_after( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process( $form_id ) {
            gf_do_action( array( 'gform_after_submission', $form_id ), $_POST, array() );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@4');
});

it('fires the name with a literal modifier exactly', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_after_submission_5', 'acme_form_five', 10, 2 );
        function acme_form_five( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process() {
            gf_do_action( array( 'gform_after_submission', 5 ), $_POST, array() );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@4');
});

it('joins a modifier held in a variable by prefix', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_after_submission_5', 'acme_form_five', 10, 2 );
        function acme_form_five( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process( $form_id ) {
            gf_do_action( array( 'gform_after_submission', $form_id ), $_POST, array() );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@4');
});

it('does not deliver to a callback on another name', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_pre_render', 'acme_other', 10, 2 );
        function acme_other( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process() {
            gf_do_action( array( 'gform_after_submission', 5 ), $_POST, array() );
        }
        PHP;

    // Only the callback's own unknown-provenance seed can report here, never
    // the dispatch's request data.
    foreach (scanModifiedHooks($source)->findings->all() as $finding) {
        foreach ($finding->trace as $step) {
            expect($step->description)->not->toContain('$_POST');
        }
    }
});

it('returns what a filter callback returns, and passes the value through', function (): void {
    $source = <<<'PHP'
        <?php
        add_filter( 'gform_pre_render', 'acme_pre_render' );
        function acme_pre_render( $form ) {
            return $_GET['title'];
        }
        function acme_render( $form_id ) {
            echo gf_apply_filters( array( 'gform_pre_render', $form_id ), 'Contact us' );
            echo gf_apply_filters( array( 'gform_other', $form_id ), $_POST['x'] );
        }
        PHP;

    $findings = modifiedHookFindings(scanModifiedHooks($source));

    expect($findings)->toContain('wp.xss.unescaped-output@7');
    expect($findings)->toContain('wp.xss.unescaped-output@8');
});

it('takes the older form, a name with the modifier as the next argument', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_after_submission', 'acme_after', 10, 2 );
        function acme_after( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process( $form_id ) {
            gf_do_action( 'gform_after_submission', $form_id, $_POST, array() );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@4');
});
