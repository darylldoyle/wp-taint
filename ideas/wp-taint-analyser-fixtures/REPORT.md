# WordPress Taint Analyser Fixture Suite: Research & Test Design Report

## Executive summary

The main recommendation is to stop treating a corpus of live plugins as the *oracle* for correctness. Mature static-analysis projects combine small, deterministic unit/regression fixtures with strict expected results, then use real repositories as a separate precision/recall validation layer.

This bundle implements that pattern as **36 scenarios / 72 variants**: 8 input-only, 10 output-only, and 18 complete flows. Every scenario has a vulnerable and corrected counterpart so a one-concept change should flip the expected result. That paired design is intentionally “metamorphic”: it catches analyzers that merely match the presence of a function name instead of reasoning about dataflow and ordering.

The most important WordPress-specific addition is an explicit **escape state machine**. Escaping is not a permanent property of a variable. If a value is passed through `apply_filters()` or another user-modifiable hook after escaping, the prior escaping guarantee is invalidated and the value must be escaped again at the eventual sink.

## What other analyzers do

### Semgrep

Semgrep colocates positive and negative expectations with source-code examples (`ruleid` / `ok`) and runs them as rule tests. Its own methodology recommends starting with concrete secure/insecure samples and then testing on real repositories. This makes tiny examples executable documentation and keeps real-world scanning from becoming the only oracle.

Sources:
- https://semgrep.dev/blog/2022/testing-autofix-behavior-of-sast-rules/
- https://semgrep.dev/blog/2020/writing-semgrep-rules-a-methodology/

### CodeQL

CodeQL has a first-class query-test runner with golden `.expected` outputs. Tests fail when results change; a `--learn` mode can rewrite expected outputs, which is useful locally but should be a reviewed operation. CodeQL also has an inline-expectations library, showing the same general preference for expectations next to test source.

Sources:
- https://github.com/github/docs/blob/main/content/code-security/reference/code-scanning/codeql/codeql-cli-manual/test-run.md
- https://codeql.github.com/codeql-standard-libraries/rust/codeql/util/test/InlineExpectationsTest.qll/module.InlineExpectationsTest.html

### PHPStan / Psalm

PHPStan extension tests explicitly assert exact error messages and lines and fail on additional errors, which is a strong model for controlling false positives. Psalm's taint docs describe explicit sources, sinks and taint kinds; a reported Psalm issue involving WordPress demonstrates that array reconstruction/merging can expose gaps in taint propagation, so this suite includes a dedicated nested-array/`array_merge()` regression.

Sources:
- https://phpstan.org/developing-extensions/testing
- https://psalm.dev/docs/security_analysis/
- https://github.com/vimeo/psalm/issues/10919

## WordPress-specific security model encoded here

WordPress' security guidance says not to trust user, database, or third-party data; to sanitize/validate input; and to escape output as late as possible. The escaping handbook explicitly notes that a value can change between an early escape and eventual output, which is why late escaping improves safety and static analysis.

Sources:
- https://developer.wordpress.org/apis/security/
- https://developer.wordpress.org/apis/security/sanitizing/
- https://developer.wordpress.org/apis/security/escaping/

The suite therefore models the following states:

```text
UNTRUSTED
  | sanitize / validate
  v
SANITIZED_FOR_STORAGE
  | persistent store / later read
  v
UNTRUSTED_FOR_OUTPUT
  | context-correct escape
  v
ESCAPED_FOR_CONTEXT
  | apply_filters / user callback / tainted concat
  v
UNTRUSTED_FOR_OUTPUT   <-- escape guarantee invalidated
  | final context-correct escape
  v
OUTPUT SINK
```

That database transition is deliberate: input sanitisation is not a substitute for output escaping. Conversely, perfectly escaped output should not hide an input-boundary violation if raw request data was persisted.

## Why 36 scenarios is a sensible stopping point

The corpus is organized by *semantic dimensions*, not by trying to enumerate every WordPress API. It covers:

- request superglobals, cookies, uploads, REST params, shortcode attrs, remote HTTP and database reads;
- scalar, nested array, merged array, object/method, branch and callback propagation;
- HTML text, attributes, URLs, rich HTML, JavaScript, textarea and XML contexts;
- storage boundaries, filter/action callbacks, global state, cross-file and cross-plugin/theme paths;
- sanitizer versus escaper distinction;
- wrong-context escaping;
- escape invalidation after filters;
- controls where input is safe but output is not, and vice versa.

Adding many more fixtures *before a real failure motivates them* will mostly create maintenance cost. The better long-term rule is: every confirmed false positive, false negative, or new CVE pattern gets reduced to the smallest reproducible paired scenario and added to this corpus.

## Real vulnerability inspiration

`O04` / `F04` model the repeated WordPress pattern where `add_query_arg()` is used to construct a URL that is later printed without `esc_url()`. CVE-2024-8730 (Exit Notifier) is one concrete example.

`F03` models the shortcode-attribute family. CVE-2025-12661 (Pollcaster Shortcode Plugin) describes stored XSS through a shortcode parameter due to insufficient input sanitisation and output escaping. Similar advisories exist for many shortcode plugins, making this a valuable regression family rather than a contrived edge case.

Sources:
- https://nvd.nist.gov/vuln/detail/CVE-2024-8730
- https://nvd.nist.gov/vuln/detail/CVE-2025-12661

## Fixture catalogue

| ID | Scenario | Vulnerable variant | Corrected variant | Expected finding |
|---|---|---|---|---|
| I01 | Direct POST to option | Raw POST data is written to an option. wp_unslash() changes slashing, not trust. | The value is unslashed and sanitized with sanitize_text_field() before storage. | `input.unsanitized_storage` |
| I02 | Nested settings array | A nested POST array is written wholesale to an option without recursively sanitizing values. | map_deep() applies sanitize_text_field() recursively before storage. | `input.unsanitized_storage` |
| I03 | Numeric GET parameter | A request value expected to be an integer reaches post meta unchanged. | absint() validates/coerces the numeric identifier before storage. | `input.unsanitized_storage` |
| I04 | Uploaded filename | The original upload name is persisted without filename sanitisation. | sanitize_file_name() is applied before writing the filename to metadata. | `input.unsanitized_storage` |
| I05 | REST request parameter | WP_REST_Request::get_param() is treated as untrusted and written to user meta directly. | sanitize_textarea_field() runs before the write. | `input.unsanitized_storage` |
| I06 | Shortcode attribute persisted | A shortcode attribute is persisted as a CSS class without sanitisation. | sanitize_html_class() constrains the class before storage. | `input.unsanitized_storage` |
| I07 | Cookie to option | A cookie value is written directly to an option. | sanitize_key() constrains the expected token-like value before storage. | `input.unsanitized_storage` |
| I08 | Remote HTTP body to option | Remote HTML is persisted without constraining allowed markup. | wp_kses_post() constrains the remote HTML before it is stored. | `input.unsanitized_storage` |
| O01 | Option in HTML text | An option value is echoed inside element text without escaping. | esc_html() is applied at the output boundary. | `output.unescaped` |
| O02 | Post meta in attribute | Post meta is interpolated into a class attribute raw. | esc_attr() is used at the attribute sink. | `output.unescaped` |
| O03 | User meta in URL attribute | User meta is used directly as an href. | esc_url() is applied at the href output boundary. | `output.unescaped` |
| O04 | add_query_arg URL output | A URL built with add_query_arg() from the current request is emitted without esc_url(). | The final URL is escaped with esc_url() at the href sink. | `output.unescaped` |
| O05 | Allowed rich HTML | Stored rich text is echoed verbatim. | wp_kses_post() permits post-safe markup while removing disallowed HTML. | `output.unescaped` |
| O06 | Inline JavaScript string | Stored data is concatenated into an inline JS string literal raw. | esc_js() is applied to the dynamic string at the JavaScript sink. | `output.unescaped` |
| O07 | Textarea context | Stored data is emitted directly between textarea tags. | esc_textarea() is applied at the output boundary. | `output.unescaped` |
| O08 | XML context | A stored URL is placed into an XML element raw. | esc_xml() is applied at the XML sink. | `output.unescaped` |
| O09 | Wrong-context escape | esc_html() is used for an href value; the value is escaped, but with the wrong semantic/context helper. | esc_url() is used for the URL attribute. | `output.wrong_context_escape` |
| O10 | Escape invalidated by filter | The value is escaped, then passed through apply_filters(), which can replace or append arbitrary data before echo. | The filter runs first and esc_html() is the final transformation before output. | `output.escape_invalidated` |
| F01 | Reflected request to HTML text | A GET parameter reaches HTML text with neither input sanitisation nor output escaping. | sanitize_text_field() is used on input and esc_html() is used at output. | `flow.unsanitized_unescaped` |
| F02 | Stored settings XSS | Raw POST data is stored, later read back, and echoed unescaped. | Input is sanitized before storage and escaped again at the later output boundary. | `flow.unsanitized_unescaped` |
| F03 | Shortcode attribute to class | A user-controlled shortcode attribute flows through shortcode_atts() and into an HTML class attribute. | The class is sanitized and escaped in the attribute context. | `flow.unsanitized_unescaped` |
| F04 | Request URI through add_query_arg | REQUEST_URI propagates through add_query_arg() into an href without URL escaping. | The composed URL is escaped only after all query-string construction is complete. | `flow.unsanitized_unescaped` |
| F05 | AJAX setting with nonce | A valid nonce is checked, but raw AJAX POST data is still stored and later echoed raw. The nonce must not clear taint. | Nonce verification remains, while the value is sanitized on input and escaped on output. | `flow.unsanitized_unescaped` |
| F06 | REST to post meta to block render | A REST parameter is stored in post meta and later rendered by a dynamic block callback without escaping. | The REST value is sanitized before storage and escaped in the block renderer. | `flow.unsanitized_unescaped` |
| F07 | Custom class propagation | Request data passes through getter and normalizer methods; trim/strtolower do not sanitize it before output. | The source is sanitized in the boundary method and escaped at output. | `flow.unsanitized_unescaped` |
| F08 | Array merge and nested access | POST data is merged into a new array, stored, retrieved, and one nested element is output raw. | The merged structure is recursively sanitized and the retrieved value is escaped at output. | `flow.unsanitized_unescaped` |
| F09 | Conditional merge | The default is trusted, but one control-flow branch assigns raw request data before the common sink. | The request branch sanitizes its value and output is escaped. | `flow.unsanitized_unescaped` |
| F10 | sprintf and concatenation | A request value flows into sprintf(), then the assembled HTML is echoed. | The dynamic value is sanitized and escaped at the point it enters the HTML template. | `flow.unsanitized_unescaped` |
| F11 | Plugin filter to theme sink | A plugin injects request data into a filter; a theme applies the filter and echoes the result raw. | The plugin sanitizes its request value and, critically, the theme escapes after apply_filters(). | `flow.unsanitized_unescaped` |
| F12 | Sanitized storage, unsafe theme output | A plugin correctly sanitizes before storage, but the theme assumes stored data is safe and echoes it raw. | The theme still escapes the database value at output. | `output.unescaped` |
| F13 | Raw storage, safely escaped theme | The theme escapes correctly, but a plugin writes raw request data to persistent storage. The input violation should still be reported. | The plugin sanitizes before storage; the theme continues to escape at output. | `input.unsanitized_storage` |
| F14 | Escaped plugin value invalidated by another plugin | Plugin A escapes a value, then exposes it to a filter. Plugin B appends request data. The theme echoes the returned value, so the original escape is no longer a valid guarantee. | Plugins return/filter data first; the theme performs the final esc_html() immediately before output. | `output.escape_invalidated` |
| F15 | Filter replaces escaped value | The theme escapes a default value before apply_filters(); another plugin completely replaces it with stored data, then the theme echoes it. | The filtered value is escaped only after all callbacks have completed. | `output.escape_invalidated` |
| F16 | Global state across action boundary | A plugin copies POST data into a global. The theme triggers an action whose plugin callback echoes the global raw. | The value is sanitized when captured and escaped inside the output callback. | `flow.unsanitized_unescaped` |
| F17 | Remote response through filter to rich HTML | Remote HTML flows through a filter and is output directly. The filter means any earlier assumptions about the remote body are insufficient. | Filtering happens first, then wp_kses_post() is the final output transformation. | `flow.unsanitized_unescaped` |
| F18 | Inline script JSON boundary | Request data is concatenated into inline JavaScript passed to wp_add_inline_script(). | The input is sanitized and wp_json_encode() is used to create a JavaScript literal before the inline-script sink. | `flow.unsanitized_unescaped` |

## How to score the analyser

For this deterministic suite, use exact counts rather than a fuzzy “looks good” score:

- **Recall** = expected vulnerable findings detected / all expected vulnerable findings.
- **Precision** = expected findings / all findings returned by the analyser on this suite.
- **Safe-variant pass rate** = safe variants with zero unexpected findings / all safe variants.
- **Classification accuracy** = findings emitted with the expected canonical kind / all expected findings.

The acceptance bar for these handcrafted fixtures should eventually be **100% recall and 100% safe-variant pass rate**. Unlike a real-world corpus, every case here has been intentionally constructed and reviewed, so a miss or extra result should be explainable rather than averaged away.

## CI recommendation

1. Run `tools/validate_suite.py` first to prove the fixture corpus is internally consistent.
2. Run the analyser across all vulnerable and safe variants.
3. Normalize analyser output to `{fixture, variant, kind}`.
4. Run `tools/compare_results.py actual.json`.
5. Fail CI on both missing and additional results.
6. Keep a separate scheduled job against live plugins/themes to track noisy real-world behaviour, but do not let that corpus define expected truth unless each result has been manually triaged.

## Next extensions, only when needed

Good future additions would be SQL taint (`$wpdb` / `prepare()`), filesystem/path taint, redirects, HTTP header sinks, and capability/authorization flows. I have intentionally kept this first bundle focused on the input-sanitisation/output-escaping contract you described rather than diluting it into a general WordPress security analyzer suite.
