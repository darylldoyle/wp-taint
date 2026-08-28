<?php

/**
 * The ten guardrails from the build spec, as executable assertions.
 *
 * Every one of these encodes a mistake that is easy to make and expensive to
 * discover late. They are pinned here rather than left as comments so that
 * re-making one fails the build.
 */

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Taint\TaintKind;

it('guardrail 1: wp_unslash is a propagator, never a sanitizer', function (): void {
    $registry = testRegistry();

    expect($registry->sanitizer(Matcher::function('wp_unslash')))->toBeNull(
        'wp_unslash() strips slashes and escapes nothing. '
            . 'If a test passes because it cleared taint, the test is wrong.',
    );

    $propagator = $registry->propagator(Matcher::function('wp_unslash'));

    expect($propagator)->not->toBeNull();
    expect($propagator->note)->toContain('NOT a sanitizer');

    $result = scanCode('<?php echo wp_unslash($_GET["q"]);');

    expect($result->findings)->toHaveCount(1);
});

it('guardrail 2: wpdb insert, update, delete and replace are never sinks', function (): void {
    $registry = testRegistry();

    foreach (['insert', 'update', 'delete', 'replace'] as $method) {
        expect($registry->sinksFor(Matcher::method('wpdb', $method)))->toBeEmpty();
        expect($registry->isSafeCall(Matcher::method('wpdb', $method)))->toBeTrue();
    }

    $result = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $wpdb->insert('wp_items', ['title' => $_POST['title']], ['%s']);
        $wpdb->update('wp_items', ['title' => $_POST['title']], ['id' => $_POST['id']]);
        $wpdb->delete('wp_items', ['id' => $_POST['id']]);
        $wpdb->replace('wp_items', ['id' => $_POST['id']]);
        PHP);

    expect($result->findings)->toHaveCount(0);
});

it('guardrail 3: prepare only sanitises with a literal format string', function (): void {
    $safe = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $wpdb->get_results($wpdb->prepare('SELECT * FROM wp_items WHERE slug = %s', $_GET['slug']));
        PHP);

    expect($safe->findings)->toHaveCount(0);

    $unsafe = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $column = $_GET['orderby'];
        $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_items ORDER BY {$column}", 10));
        PHP);

    expect($unsafe->findings->all()[0]->ruleId)->toBe('wp.sqli.prepare-non-literal');
});

it('guardrail 3b: interpolating a wpdb table property is still literal enough', function (): void {
    // The standard WordPress idiom. Flagging it would be a false positive on
    // essentially every plugin in existence.
    $result = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}items WHERE slug = %s", $_GET['slug']));
        PHP);

    expect($result->findings)->toHaveCount(0);
});

it('guardrail 4: esc_url_raw is not an HTML escaper', function (): void {
    $registry = testRegistry();
    $sanitizer = $registry->sanitizer(Matcher::function('esc_url_raw'));

    expect($sanitizer)->not->toBeNull();
    expect($sanitizer->clears->has(TaintKind::Url))->toBeTrue();
    expect($sanitizer->clears->has(TaintKind::Html))->toBeFalse();

    $result = scanCode('<?php echo esc_url_raw($_GET["u"]);');

    expect($result->findings)->toHaveCount(1);
    expect($result->findings->all()[0]->kind)->toBe(TaintKind::Html);
});

it('guardrail 5: a parse failure is reported, never skipped', function (): void {
    $result = scanCode('<?php function ( { broken');

    expect($result->parseErrors)->toHaveCount(1);
    expect($result->hasParseErrors())->toBeTrue();
    expect($result->filesScanned)->toBe(0);
});

it('guardrail 6: the analysis path makes no network calls', function (): void {
    // Enforced structurally: nothing under src/ may reference a network
    // function or a URL scheme.
    $offenders = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(projectRoot() . '/src', FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        foreach (['curl_init', 'fsockopen', 'stream_socket_client', 'file_get_contents(\'http'] as $needle) {
            if (str_contains($source, $needle)) {
                $offenders[] = $file->getPathname() . ' → ' . $needle;
            }
        }
    }

    expect($offenders)->toBe([], 'The analysis path must be fully deterministic and offline.');
});

it('guardrail 7: output is sorted by file, line, column, rule', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        echo $_GET['c'];
        echo $_GET['a'];
        eval($_POST['x']);
        PHP);

    $lines = array_map(static fn (object $f): int => $f->line, $result->findings->all());
    $sorted = $lines;
    sort($sorted);

    expect($lines)->toBe($sorted);
});

it('guardrail 8: every finding carries a trace', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        $x = $_GET['q'];
        echo '<p>' . $x . '</p>';
        PHP);

    foreach ($result->findings as $finding) {
        expect($finding->trace)->not->toBeEmpty();
        expect($finding->trace[0]->verb->value)->toBe('source');
        $trace = $finding->trace;
        expect($trace[count($trace) - 1]->verb->value)->toBe('sink');
    }
});

it('guardrail 10: an unmodelled function is treated as clean, not as a source', function (): void {
    // A documented false negative beats an undocumented false positive.
    $result = scanCode('<?php echo acme_some_helper_we_have_never_heard_of();');

    expect($result->findings)->toHaveCount(0);
});

it('models $_SERVER per key rather than wholesale', function (): void {
    $tainted = scanCode('<?php echo $_SERVER["REQUEST_URI"];');
    $clean = scanCode('<?php echo $_SERVER["SERVER_NAME"];');
    $header = scanCode('<?php echo $_SERVER["HTTP_X_FORWARDED_FOR"];');

    expect($tainted->findings)->toHaveCount(1);
    expect($header->findings)->toHaveCount(1);
    expect($clean->findings)->toHaveCount(0);
});

it('treats a dynamic superglobal key as tainted', function (): void {
    // An attacker who controls the index controls the value.
    $result = scanCode(<<<'PHP'
        <?php
        $key = 'SERVER_NAME';
        echo $_SERVER[$key];
        PHP);

    expect($result->findings)->toHaveCount(1);
});

it('keeps taint kinds separate across sanitizers', function (): void {
    // The single most important modelling decision: esc_html() does nothing
    // for SQL, and esc_sql() does nothing for HTML.
    $sqlAfterEscHtml = scanCode(<<<'PHP'
        <?php
        global $wpdb;
        $slug = esc_html($_GET['slug']);
        $wpdb->query("SELECT * FROM wp_items WHERE slug = '{$slug}'");
        PHP);

    expect($sqlAfterEscHtml->findings->all()[0]->kind)->toBe(TaintKind::Sql);

    $htmlAfterEscSql = scanCode('<?php echo esc_sql($_GET["slug"]);');

    expect($htmlAfterEscSql->findings->all()[0]->kind)->toBe(TaintKind::Html);
});

it('does not report stored writes unless asked', function (): void {
    $code = '<?php update_option("acme_last", $_GET["s"]);';

    expect(scanCode($code)->findings)->toHaveCount(0);
    expect(scanCode($code, registry: testRegistry('wordpress', true, true))->findings)->toHaveCount(1);
});

it('drops stored sources under --no-stored-taint', function (): void {
    $code = '<?php echo get_option("acme_banner");';

    expect(scanCode($code)->findings)->toHaveCount(1);
    expect(scanCode($code, registry: testRegistry('wordpress', false, false))->findings)->toHaveCount(0);
});
