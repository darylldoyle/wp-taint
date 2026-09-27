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
    // A filter, because a prefix join would run an action's callback too. Only
    // an exact match adds a filter callback's return to the result.
    $source = <<<'PHP'
        <?php
        add_filter( 'gform_pre_render_5', 'acme_form_five' );
        function acme_form_five( $form ) {
            return $_GET['title'];
        }
        function acme_render() {
            echo gf_apply_filters( array( 'gform_pre_render', 5 ), 'Contact us' );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@7');
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

it('passes the older form\'s value through, not its modifier', function (): void {
    $source = <<<'PHP'
        <?php
        function acme_upload_path( $form_id ) {
            echo gf_apply_filters( 'gform_media_upload_path', $form_id, $_GET['path'] );
        }
        function acme_label() {
            echo gf_apply_filters( 'gform_label', $_GET['form'], 'Contact us' );
        }
        PHP;

    $findings = modifiedHookFindings(scanModifiedHooks($source));

    expect($findings)->toContain('wp.xss.unescaped-output@3');
    expect($findings)->not->toContain('wp.xss.unescaped-output@6');
});

it('fires every name an older-form array of modifiers spells, exactly', function (): void {
    // A prefix join would run the callback too, but would not add its return
    // to the result. Only an exact match does.
    $source = <<<'PHP'
        <?php
        add_filter( 'gform_field_label_5_7', 'acme_field_label' );
        function acme_field_label( $label ) {
            return $_GET['label'];
        }
        function acme_render() {
            echo gf_apply_filters( 'gform_field_label', array( 5, 7 ), 'Name' );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@7');
});

it('reads a name and modifiers held in a variable as the array form', function (): void {
    $source = <<<'PHP'
        <?php
        add_action( 'gform_after_submission_5', 'acme_form_five', 10, 2 );
        function acme_form_five( $entry, $form ) {
            echo $entry['name'];
        }
        function acme_process() {
            $hook = array( 'gform_after_submission', 5 );
            gf_do_action( $hook, $_POST, array() );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.xss.unescaped-output@4');
});

it('does not credit an AJAX handler with a check inside a callback on its hook', function (): void {
    // The callback's check decides what the filter does to the form. It does
    // not decide who may call the handler.
    $source = <<<'PHP'
        <?php
        add_action( 'wp_ajax_nopriv_acme_form', 'acme_ajax_form' );
        add_filter( 'gform_form_post_get_meta', 'acme_restrict_fields' );
        function acme_restrict_fields( $form ) {
            if ( is_super_admin() ) {
                return $form;
            }
            $form['fields'] = array();
            return $form;
        }
        function acme_get_form( $form_id ) {
            return gf_apply_filters( array( 'gform_form_post_get_meta', $form_id ), get_option( 'acme_form' ) );
        }
        function acme_ajax_form() {
            wp_send_json( acme_get_form( 5 ) );
        }
        PHP;

    expect(modifiedHookFindings(scanModifiedHooks($source)))->toContain('wp.authz.ajax-missing-check@2');
});
