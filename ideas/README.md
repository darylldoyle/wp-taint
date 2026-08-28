# WordPress Taint Analyser Fixture Suite

A deterministic regression corpus for a WordPress-aware taint analyser.

## What is in the box

- **36 scenarios / 72 code variants**.
- Every scenario has a deliberately vulnerable variant and a corrected variant.
- 8 input-only scenarios, 10 output-only scenarios, and 18 full source-to-sink flows.
- Cross-file, cross-plugin, and plugin-to-theme fixtures.
- Explicit regressions for WordPress hooks invalidating an earlier output escape.
- Canonical expectations in `expected-findings.json` and per-variant `expected.json` files.
- Inline markers beside the relevant source/sink so failures are easy to inspect.
- A strict comparator and suite validator in `tools/`.
- Realistic `wp-content/plugins/...` and `wp-content/themes/...` layouts inside each variant.
- `model-vocabulary.json` and `coverage-matrix.csv` for adapter/model coverage work.

## The test contract

The suite intentionally distinguishes four ideas that are often collapsed together:

1. **Input sanitisation**: request/external data should be constrained before it is persisted or otherwise trusted for processing.
2. **Output escaping**: data is considered untrusted again when read for output and must be escaped for its final context.
3. **Context correctness**: `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()`, `esc_textarea()`, `esc_xml()` and KSES are not interchangeable.
4. **Escape invalidation**: after a value is escaped, passing it through a user-modifiable WordPress hook/filter makes that escape guarantee invalid. Escape after the last hook.

This models WordPress' “escape late” guidance and makes the analyser prove *when* a value became safe, not merely whether an escaping function appeared somewhere upstream.

## Inline markers

Fixtures use comments such as:

```php
// @wp-taint-source F14
// @wp-taint-invalidate F14 reason=filter-after-escape
// @wp-taint-sink F14 expect=output.escape_invalidated
```

The marker line is the assertion anchor. Your adapter can report the sink expression line instead if preferred; preserve the fixture id + canonical finding kind when normalising results.

## Canonical finding kinds

- `input.unsanitized_storage`
- `output.unescaped`
- `output.wrong_context_escape`
- `output.escape_invalidated`
- `flow.unsanitized_unescaped`
- `clean` (used only as an inline expectation, never as a finding)

## Running the suite

First validate the corpus itself:

```bash
python3 tools/validate_suite.py
```

Then run your analyser over `fixtures/` and write a *normalised* JSON array in this shape:

```json
[
  {
    "fixture": "F14",
    "variant": "vulnerable",
    "kind": "output.escape_invalidated"
  }
]
```

Compare it strictly:

```bash
python3 tools/compare_results.py actual.json
```

By default the comparator ignores source line numbers and paths, because different analyzers choose different locations for path findings. It deliberately fails on both false negatives **and false positives**.

## Recommended CI layers

Use this fixture suite as the deterministic layer. Keep the live-plugin corpus too, but give it a different job:

- **Fixture regression suite**: exact correctness; zero unexplained deltas.
- **Curated real-world corpus**: precision/recall trends and regression hunting.
- **New vulnerability regressions**: every analyser bug or confirmed CVE pattern should be reduced to a minimal fixture and added here.

Do not automatically “learn” changed expectations in CI. A golden-output update should be a reviewed change because a changed result can represent either an analyser improvement or a regression.

See `REPORT.md` for the rationale and a fixture-by-fixture description.
