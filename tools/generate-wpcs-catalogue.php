<?php

/**
 * Regenerates `registries/wordpress-generated.toml` from the WordPress Coding
 * Standards function lists.
 *
 * WPCS curates the lists this tool most needs and least wants to maintain by
 * hand: which functions escape, which sanitise, which unslash, which print.
 * They are reviewed by people who work on WordPress security full time, and
 * they change with each release.
 *
 * ## What this does and does not decide
 *
 * WPCS says *that* `esc_attr()` escapes. It does not say *which taint kinds* it
 * clears, because a token-based sniff has no concept of kinds — and that
 * distinction is the single most important modelling decision in this engine.
 * `esc_url_raw()` is on the escaping list and is emphatically not an HTML
 * escaper.
 *
 * So the kinds come from the table below, written by hand, and a function whose
 * kinds are not stated is **skipped rather than guessed**. Generating an entry
 * that clears the wrong kind would launder real taint, which is the worst thing
 * this tool can do.
 *
 * The generated file is loaded *before* the hand-written catalogue, so any
 * hand-written entry wins.
 *
 * Usage: php tools/generate-wpcs-catalogue.php [--check]
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

const OUTPUT = __DIR__ . '/../registries/wordpress-generated.toml';

/**
 * What each escaping or sanitising function actually clears.
 *
 * Absent from this table means absent from the output. Adding a function here is
 * a security decision and should be reviewed as one: the question is not "does
 * WPCS list it" but "which taint kinds can no longer be carried by the value it
 * returns".
 *
 *
 */
const KINDS = [
    // Numeric casts. Nothing survives becoming a number.
    'absint' => '*',
    'intval' => '*',
    'floatval' => '*',
    'number_format' => '*',

    // HTML element context.
    'esc_html' => ['html', 'html_attr'],
    'esc_html__' => ['html', 'html_attr'],
    'esc_html_e' => ['html', 'html_attr'],
    'esc_html_x' => ['html', 'html_attr'],
    'esc_textarea' => ['html', 'html_attr'],
    'wp_kses' => ['html', 'html_attr'],
    'wp_kses_post' => ['html', 'html_attr'],
    'wp_kses_data' => ['html', 'html_attr'],
    'sanitize_text_field' => ['html', 'html_attr'],
    'sanitize_textarea_field' => ['html', 'html_attr'],

    // Attribute context only. esc_attr() does not make a value safe to place
    // outside quotes, but it does close the quote-escape hole.
    'esc_attr' => ['html', 'html_attr'],
    'esc_attr__' => ['html', 'html_attr'],
    'esc_attr_e' => ['html', 'html_attr'],
    'esc_attr_x' => ['html', 'html_attr'],

    // Identifier-shaped output: what comes back cannot carry markup or SQL.
    'sanitize_key' => '*',
    'sanitize_html_class' => ['html', 'html_attr', 'sql'],
    'sanitize_user' => ['html', 'html_attr', 'sql'],
    'sanitize_file_name' => ['html', 'html_attr', 'path'],
    'sanitize_title' => ['html', 'html_attr', 'sql'],
    'sanitize_title_for_query' => ['html', 'html_attr', 'sql'],
    'sanitize_title_with_dashes' => ['html', 'html_attr', 'sql'],
    'sanitize_sql_orderby' => ['sql'],

    // SQL.
    'esc_sql' => ['sql'],
    'like_escape' => ['sql'],

    // JavaScript string context.
    'esc_js' => ['html', 'html_attr'],

    // URLs. esc_url() is for HTML attributes; esc_url_raw() is for redirects
    // and storage and escapes nothing for display — a distinction WPCS's flat
    // list cannot express and this engine turns on.
    'esc_url' => ['html', 'html_attr', 'url'],
    'esc_url_raw' => ['url'],
    'sanitize_url' => ['url'],

    // Email and mail headers.
    'sanitize_email' => ['html', 'html_attr', 'header'],
    'is_email' => ['html', 'html_attr', 'header'],

    // XML.
    'esc_xml' => ['html', 'html_attr'],

    // Comparison, not transformation, but the result is a boolean.
    'hash_equals' => '*',

    // Percent-encoding. What comes out has no quote, angle bracket, slash or
    // backslash left in it, so it cannot carry syntax into any of these
    // contexts. Not `url`: an encoded value is still attacker data, it just
    // cannot change the host it is appended to.
    'urlencode' => ['html', 'html_attr', 'sql', 'path', 'shell', 'header', 'ldap', 'xpath'],
    'rawurlencode' => ['html', 'html_attr', 'sql', 'path', 'shell', 'header', 'ldap', 'xpath'],
    'urlencode_deep' => ['html', 'html_attr', 'sql', 'path', 'shell', 'header', 'ldap', 'xpath'],

    // Shape-restricted output: a hex colour, a locale, a tag name, a list of
    // integers. None of them can be anything else afterwards.
    'sanitize_hex_color' => '*',
    'sanitize_hex_color_no_hash' => '*',
    'sanitize_locale_name' => '*',
    'tag_escape' => '*',
    'wp_parse_id_list' => '*',

    'sanitize_mime_type' => ['html', 'html_attr', 'sql', 'path'],
    'wp_kses_one_attr' => ['html', 'html_attr'],

    // Strips the characters that split a header.
    'wp_sanitize_redirect' => ['header'],
];

/**
 * Functions on a WPCS list that this deliberately does not generate.
 *
 * Recorded so the omission is a decision on the record rather than a gap
 * somebody has to rediscover.
 *
 */
const SKIPPED = [
    'filter_input' => 'What it clears depends entirely on the filter constant passed to it.',
    'filter_var' => 'Same: FILTER_SANITIZE_URL and FILTER_VALIDATE_INT clear very different things.',
    'json_encode' => 'Context-sensitive. Modelled by hand as clearing html, and marked imprecise.',
    'wp_json_encode' => 'Same as json_encode.',
    'highlight_string' => 'Returns markup by design.',
    'wp_rel_nofollow' => 'Rewrites attributes; does not escape the value.',
    '_wp_handle_upload' => 'Returns a structure, not a scalar. Needs per-key modelling.',
    'wp_redirect' => 'A sink, not an escaper.',
    'wp_safe_redirect' => 'Validates the host rather than escaping; modelled by hand.',
    'validate_file' => 'Returns a status code, not a sanitised path.',
    'wp_strip_all_tags' => 'Removes tags but leaves quotes and ampersands. Modelled by hand as a propagator.',
    'wp_handle_upload' => 'Returns a structure, not a scalar.',
    'wp_handle_sideload' => 'Returns a structure, not a scalar.',
    'wp_kses_allowed_html' => 'Returns the allowlist, not a sanitised value.',
    'sanitize_meta' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_option' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_term' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_term_field' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_user_field' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_bookmark' => 'Applies a filter, so what it clears depends on the callbacks registered.',
    'sanitize_bookmark_field' => 'Applies a filter, so what it clears depends on the callbacks registered.',
];

/**
 * @return array<string, true>
 */
function wpcsList(string $file, string $property): array
{
    $source = file_get_contents($file);

    if ($source === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', $file));
    }

    // The lists are plain array literals in a trait. Parsing the file with
    // php-parser would be tidier and would also require the trait's class
    // hierarchy to exist; a scoped regex over a literal is enough.
    $pattern = sprintf('/\$%s\s*=\s*array\s*\((?<body>.*?)\n\s*\);/s', preg_quote($property, '/'));

    if (preg_match($pattern, $source, $matches) !== 1 || ! isset($matches['body'])) {
        throw new RuntimeException(sprintf('Cannot find $%s in %s.', $property, $file));
    }

    preg_match_all("/'([^']+)'\s*=>\s*true/", $matches['body'], $names);

    $list = [];

    foreach ($names[1] as $name) {
        $list[$name] = true;
    }

    return $list;
}

$wpcs = __DIR__ . '/../vendor/wp-coding-standards/wpcs/WordPress/Helpers';

$escaping = wpcsList($wpcs . '/EscapingFunctionsTrait.php', 'escapingFunctions');
$sanitizing = wpcsList($wpcs . '/SanitizationHelperTrait.php', 'sanitizingFunctions');
$unslashing = wpcsList($wpcs . '/UnslashingFunctionsHelper.php', 'unslashingFunctions');

$clearing = $escaping + $sanitizing;
ksort($clearing);

$lines = [
    '# Generated from the WordPress Coding Standards function lists.',
    '# Do not edit by hand: run `composer catalogue:generate`.',
    '#',
    '# WPCS says *that* a function escapes. It does not say which taint kinds it',
    '# clears, because a token-based sniff has no concept of kinds — and that is the',
    '# most important modelling decision in this engine. The kinds come from a table',
    '# in tools/generate-wpcs-catalogue.php, written by hand and reviewed as a',
    '# security decision; a function whose kinds are not stated is skipped rather',
    '# than guessed, because generating the wrong kind would launder real taint.',
    '#',
    '# Loaded before the hand-written catalogue, so any hand-written entry wins.',
    '',
    '[meta]',
    'extends = ["php-core"]',
    'name = "wordpress-generated"',
    'description = "Escapers, sanitizers and unslashers imported from WPCS"',
    '',
];

$generated = 0;
$skipped = [];

foreach (array_keys($clearing) as $name) {
    if (! isset(KINDS[$name])) {
        $skipped[] = $name;

        continue;
    }

    $kinds = KINDS[$name];

    $lines[] = '[[sanitizers]]';
    $lines[] = sprintf('function = "%s"', $name);
    $lines[] = is_string($kinds)
        ? 'clears = "*"'
        : sprintf('clears = [%s]', implode(', ', array_map(
            static fn (string $kind): string => sprintf('"%s"', $kind),
            $kinds,
        )));
    $lines[] = '';
    $generated++;
}

foreach (array_keys($unslashing) as $name) {
    // Unslashing is not escaping, and treating it as such is the single most
    // common way a WordPress codebase convinces itself it is safe. Guardrail 1
    // in the test suite exists to keep it that way.
    $lines[] = '[[propagators]]';
    $lines[] = sprintf('function = "%s"', $name);
    $lines[] = 'note = "Removes backslashes. Escapes nothing."';
    $lines[] = '';
    $generated++;
}

$toml = implode("\n", $lines);
$check = in_array('--check', $argv, true);

if ($check) {
    $current = is_file(OUTPUT) ? file_get_contents(OUTPUT) : '';

    if ($current !== $toml) {
        fwrite(STDERR, "registries/wordpress-generated.toml is stale. Run: composer catalogue:generate\n");

        exit(1);
    }

    echo "Generated catalogue is up to date.\n";

    exit(0);
}

file_put_contents(OUTPUT, $toml);

printf(
    "Wrote %d entries to registries/wordpress-generated.toml.\n%d WPCS functions skipped for want of a kinds entry:\n",
    $generated,
    count($skipped),
);

foreach ($skipped as $name) {
    printf("  %-30s %s\n", $name, SKIPPED[$name] ?? 'no kinds stated');
}
