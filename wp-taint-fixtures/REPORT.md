# WordPress Taint Analyser — Fixture Suite Report

## Summary

This suite gives your analyser a labelled corpus with known ground truth, so
"is it working?" becomes a number instead of a judgement call. It contains 109
annotated cases across 18 rule IDs, split into 64 expected true positives and 44
expected true negatives, plus one stretch case marked informational.

The design follows the methodology established by OWASP Benchmark, NIST Juliet,
and Semgrep's own rule-testing convention: pair every vulnerable case with a
safe counterpart, label both, and measure true/false positive and negative rates
rather than eyeballing output. False negatives matter more than false positives
here — a missed injection ships, a false alarm only wastes a review — so the
scorer reports recall per rule and fails CI on any miss.

## How other taint tools test themselves

The research converged on four practices, all of which this suite adopts:

- **Paired good/bad cases with ground-truth labels.** Juliet uses `good()`/
  `bad()` method naming; OWASP Benchmark ships an XML label per case; Semgrep
  uses inline `ruleid:`/`ok:` comments. Labelling both the vulnerable and the
  safe version is what lets you measure false positives, not just detection.
- **Inline expectation annotations adjacent to the finding.** Semgrep's
  `ruleid`/`ok`/`todoruleid`/`todook` grammar keeps the expected result next to
  the code and travels with the fixture. This suite reuses that exact grammar so
  the fixtures double as documentation.
- **ROC-style scoring: TPR and FPR, not raw counts.** OWASP Benchmark plots
  results on a true-positive-rate vs false-positive-rate chart; a tool that
  flags everything scores 100% recall and is still useless. `tools/score.py`
  reports precision, recall, and F1 per rule and overall.
- **Synthetic suites plus real-CVE cross-checks.** The literature is explicit
  that paired synthetic cases inflate apparent accuracy and under-represent real
  complexity (BenchPress, "Benchmarking the Benchmarks"). The `06-cve-inspired/`
  set mitigates this by modelling real vulnerability *classes* with the
  interprocedural and cross-component structure that catches naive matchers,
  while staying entirely synthetic — no real plugin code is referenced or
  reproduced.

The known limitation, per the same research: a synthetic suite proves the
analyser handles the patterns you thought of. It does not prove coverage of
patterns you didn't. Treat a green run as necessary, not sufficient, and keep
feeding it real findings from live scans as regression cases.

## What each category tests

### 01-input — source recognition and sanitiser allowlisting

Tests the input half in isolation: does the analyser know its sources, and does
it have a real allowlist of sanitisers rather than treating any function call as
cleansing?

- `sanitisers-recognised.php` — 10 core WP sanitisers used correctly. All safe.
  Any finding here is a false positive against the sanitiser catalogue.
- `unsanitised-inputs.php` — raw `$_POST`/`$_GET`/`$_REQUEST`/`$_COOKIE`/
  `$_SERVER`, `php://input`, and `get_query_var()` persisted without cleaning.
  All vulnerable. Note `wp_unslash()` is present but is not sanitisation.
- `insufficient-sanitisers.php` — the trap cases: `trim()`, `stripslashes()`,
  `strtolower()`, `substr()` look like cleaning but preserve payloads; a nonce
  or capability check authorises the actor but does not clean the value;
  `is_email()` validates without rejecting. Each must still flag.
- `conditional-sanitisation.php` — path sensitivity. One branch sanitising while
  another doesn't must flag; both branches sanitising must not; guard-clause
  `return` and strict `in_array(...,true)` whitelists are safe; a loose
  `in_array()` is the one `todoruleid` stretch case (requires modelling
  comparison strictness).

### 02-output — sink recognition and escaper-context correctness

Tests the output half in isolation, assuming values arrive already tainted.

- `escapers-recognised.php` — correct late-escaping with `esc_html`, `esc_url`,
  `esc_attr`, `wp_kses_post`, `esc_textarea`, integer casts. All safe.
- `unescaped-output.php` — tainted values into `echo`/`print`/`printf`, including
  taint in the printf *format string* and heredoc interpolation. All vulnerable.
- `wrong-escaper-for-context.php` — the subtle set: `esc_html` inside a `<script>`
  block, `esc_attr` on an `href` (survives `javascript:`), `esc_html` on an
  unquoted attribute. An escaper is present but wrong for the context — a naive
  "an esc_* call exists, so safe" check fails every case here.
- `attribute-and-uri-contexts.php` — quoted vs unquoted attribute boundaries and
  URI-scheme handling, mixing safe and vulnerable.

### 03-flows — full source-to-sink

The core of the suite: taint that travels from a source to a sink.

- `direct-reflected-xss.php` — the canonical smoke test, plus the convention
  case where a value is sanitised at input but still not escaped at output.
- `stored-xss-roundtrip.php` — taint crosses a persistence boundary: stored raw
  via `update_user_meta`, read back with `get_user_meta`, echoed raw. Requires
  treating persisted reads as tainted when the write was tainted.
- `sql-injection.php` — `$wpdb` concatenation and interpolation (vulnerable),
  correct `prepare()` with placeholders (safe), and the decoy where a value is
  concatenated *into* the query before `prepare()` sees it (vulnerable).
- `interprocedural-flow.php` — taint through return values, through a sanitising
  middle layer, through an escaping callee, and through an array element
  (field-sensitivity).
- `sink-in-callback.php` — taint reaching a sink inside a closure captured by
  `add_action` and inside a shortcode callback. A common blind spot.

### 04-post-escape-mutation — the house rule

This is the category most third-party analysers get wrong and the reason this
suite exists. Under your convention, an escaped value that becomes user-
modifiable again voids the escape. Every file here has a visible, correct
`esc_*` call and is still vulnerable because a hook, filter, or shortcode mutates
the value after the escape.

- `filtered-after-escape.php` — escaped, then `apply_filters` lets a third-party
  callback rewrite it before echo. Also the correct ordering (filter first,
  escape last) for contrast, plus concatenation with a filtered fragment and
  token replacement supplied by a filter.
- `shortcode-do_shortcode-after-escape.php` — escaped, then `do_shortcode`
  expands tags that a registered shortcode can fill with raw HTML.
- `sprintf-reintroduction.php` — escaped format string, tainted unescaped
  argument.
- `hook-mutation-notes.md` — the modelling rule: track escape *position*
  relative to the sink, treat extension points as taint re-introduction, and
  require the escape to be the last transformation before the sink.

A checker that only asks "is there an `esc_*` on the path?" scores every
vulnerable file here as safe. That's the specific failure this category catches.

### 05-cross-component — taint across plugin/theme boundaries

The hardest capability: source in one component, sink in another, linked only by
the hook system or a shared option. A single-file analyser cannot see these; the
engine must resolve `do_action`/`apply_filters` names to their handlers across
the whole scanned tree.

- `plugin-a/` collects input, stores a raw option, and fires `do_action(
  'fx_a_after_submit', $raw )`.
- `plugin-b/` hooks that action and echoes the payload (sink in a different
  file), and separately injects a raw request value into plugin-a's filter,
  which plugin-a then echoes (source in plugin-b, sink in plugin-a).
- `theme/` reads plugin-a's stored option and renders it in a template part.

Expected findings deliberately span files. If your analyser only reports
within-file flows, this category is where that shows up.

### 06-cve-inspired — real vulnerability classes, synthetic code

Each file models a class of bug that recurs across the WordPress ecosystem,
abstracted to a generic `fx_*` plugin. No real plugin code is referenced or
reproduced, and none is exploitable as written. These exist to push beyond
simple single-line cases and to exercise non-XSS sink families.

- `admin-ajax-nopriv-xss.php` — unauthenticated `wp_ajax_nopriv_*` reflecting a
  param (CWE-79).
- `rest-callback-injection.php` — `register_rest_route` callback trusting
  `$request->get_param()`, with an open `permission_callback`; XSS and SQLi
  variants (CWE-79 / CWE-89).
- `settings-callback-stored-xss.php` — Settings API field with no
  `sanitize_callback`, printed unescaped in the field renderer (CWE-79).
- `csv-formula-injection.php` — exported CSV built from stored input with no
  formula neutralisation (CWE-1236). Tests whether the sink model knows the CSV
  context needs its own neutraliser, distinct from HTML escaping.
- `open-redirect-and-ssrf.php` — `wp_redirect` with a raw destination (CWE-601)
  and `wp_remote_get` on a user-controlled URL (CWE-918).
- `php-object-injection.php` — `unserialize()` on a request value (CWE-502).
- `path-traversal-file-read.php` — user-controlled path into `file_get_contents`,
  with a `basename()`-contained safe variant (CWE-22).

## Scoring and CI

`tools/score.py` matches reported findings to manifest entries by file and line
(±2 lines by default, since a sink can span several lines), optionally requiring
the rule ID to match with `--by-rule`. It prints TP/FN/FP/TN with precision,
recall, and F1 per rule and overall, and exits non-zero on any miss or false
alarm.

Verified against a synthetic perfect run: 64/64 true positives, 0 false
negatives, 0 false positives, F1 = 1.00, exit 0.

## Recommended next steps

1. **Run `php -l` across all 27 fixtures on your side.** PHP isn't installable in
   the environment these were built in, so they passed a structural check
   (balanced braces, open tags) but not a real lint. They're written to parse,
   but verify before wiring into CI.
2. **Baseline your current analyser** against the suite and record the per-rule
   scorecard. The gaps tell you where to invest.
3. **Expect `04-post-escape-mutation` and `05-cross-component` to be the hard
   categories.** If those score well, the engine is doing the WordPress-specific
   work that off-the-shelf tools skip.
4. **Feed real findings back in as regression fixtures.** The synthetic suite
   proves the patterns you anticipated; live scan results are how you close the
   gap the research warns about.
5. **Tune the stretch case** (`conditional-sanitisation.php` loose `in_array`).
   Promote `todoruleid` to `ruleid` once the analyser models comparison
   strictness, and it becomes a real regression guard.
