# Benchmark

wp-taint against the two tools it would actually be chosen over, on the same
fixture suite. The suite was written before the engine existed, precisely so
this comparison would be cheap and honest.

Run on macOS 15 (arm64), PHP 8.3.32, on 68 vulnerable and 73 safe fixtures.

| | wp-taint | Semgrep 1.174 | Psalm 6.16 |
| --- | --- | --- | --- |
| **Vulnerable caught** | **68 / 68** (100%) | 64 / 68 (94.1%) | 31 / 68 (45.6%) |
| **False positives on `safe/`** | **0 / 73** (0%) | 9 / 73 (12.3%) | 4 / 73 (5.5%) |
| Time on the fixture tree | **0.3s** | 1.9s | 3.1s |
| Time on Akismet (7.7k lines) | **1.2s** | — | 3.4s |
| Configuration | none | hand-written 12-rule pack | `php-stubs/wordpress-stubs` |

The safe half is the half that matters. A tool that cries wolf gets muted and
then deleted, at which point its true positives stop counting.

## By vulnerability class

| Class | Fixtures | wp-taint | Semgrep | Psalm |
| --- | ---: | ---: | ---: | ---: |
| XSS | 34 | **34** | 32 | 19 |
| SQL injection | 12 | **12** | 11 | 0 |
| RCE (eval, shell, unserialize) | 6 | **6** | 6 | 5 |
| LFI / path | 5 | **5** | 5 | 5 |
| REST authorization | 4 | **4** | 4 | 0 |
| AJAX authorization | 4 | **4** | 3 | 0 |
| Redirect / header | 3 | **3** | 3 | 2 |

Semgrep's four misses are `ajax-missing-check-method-callback`,
`sqli-structural-unprepared-interpolation`, `xss-enum-method` and
`xss-match-expression`.

## What each tool got wrong, and why

### Psalm — 31/68, 4 false positives

Psalm has a real interprocedural taint engine, and where it works it works well.
Two things stop it on WordPress.

**It catches 0 of 12 SQL injections.** Psalm's taint model has no idea what
`$wpdb` is. `php-stubs/wordpress-stubs` declares the class, but nothing marks
`wpdb::query()` as a sink or `wpdb::prepare()` as a sanitizer, so every
`$wpdb->query( "… {$_GET['x']} …" )` passes silently. That is the single largest
gap and it is a catalogue gap, not an engine one — it would be fixable with a
Psalm plugin nobody has written.

**It catches 0 of 8 authorization bugs.** Expected: a missing
`permission_callback` has no source and no sink. Taint analysis structurally
cannot find it, which is exactly why wp-taint has structural rules alongside the
dataflow engine.

**Its 4 false positives are all interprocedural sanitisation:**

```php
function render_heading( $label ) {
    return '<h2>' . esc_html( $label ) . '</h2>';   // escaped inside the callee
}

echo render_heading( $_GET['report_filter'] );      // Psalm reports this
```

Psalm does not credit `esc_html()` here because the stubs do not mark it as a
sanitizer for the taint type it is tracking. Again: a catalogue problem.

### Semgrep — 64/68, 9 false positives

Semgrep did well, and better than the plan expected. The 12-rule pack in
`docs/benchmark-semgrep-rules.yml` uses Semgrep's own `mode: taint` with the
same sources, sanitizers and sinks as `registries/wordpress.toml`, so this is a
fair fight rather than a straw man.

**AJAX authorization costs it accuracy in both directions.** A Semgrep rule
matches one AST node, and `add_action( 'wp_ajax_x', 'handler' )` and
`function handler() { … }` are different nodes in different places, so no single
rule can see the registration *and* the body. The pack works around it two ways:
an inline-closure rule, which is exact, and a rule that flags any function whose
name contains `ajax` and which has no check anywhere in it. That gets 3 of 4 —
it misses the `[$this, 'method']` callback form entirely — and costs a false
positive on `ajax-closure-with-check.php`, where the check sits inside an `if`
condition that Semgrep's statement-position `...` cannot see.

**It misses `match` and `enum`** (`xss-match-expression`, `xss-enum-method`).
Semgrep's PHP taint mode does not follow a value through a `match` arm or an
enum method body. wp-taint only handles those because php-cfg cannot parse them
either, and `Cfg\CompatibilityVisitor` lowers them first.

**It misses the shape-only SQL case** (`sqli-structural-unprepared-interpolation`),
where a variable is interpolated into a query but comes from a helper no tool can
resolve. Taint analysis correctly reports nothing; wp-taint reports it from
`Taint\QueryShapeInspector` instead, which fires exactly where dataflow had
nothing to say.

**Its 9 false positives split into three groups.** Five are interprocedural
sanitisation — the same shape Psalm fails on, and the documented limit of
Semgrep's single-file cross-function taint. One is the AJAX case above. The
other three are `prepare()`:

```php
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items WHERE slug = %s", $slug ) );
```

This is the standard, correct WordPress idiom. A Semgrep sanitizer pattern of
`$DB->prepare("...", ...)` matches a plain string literal but not an
interpolated one, so the whole call stops counting as a sanitizer.

Broadening the pattern to `$DB->prepare(...)` fixes those three but loses the
two real `prepare()`-with-a-non-literal-format-string findings:

| prepare() sanitizer pattern | Vulnerable caught | False positives |
| --- | ---: | ---: |
| `$DB->prepare("...", ...)` (strict) | 64 / 68 | 9 / 73 |
| `$DB->prepare(...)` (lenient) | 62 / 68 | 6 / 73 |

There is no pattern that gets both, because the distinction is *"is this format
string built from anything attacker-controlled"* — a dataflow question, not a
syntactic one. wp-taint answers it in `Taint\LiteralAnalyzer`, and that is the
clearest single illustration of why the dataflow engine earns its keep.

## Is this comparison fair?

Where it is not, it is unfair **to wp-taint**:

- The fixture suite was written by this project. It was written before the
  engine, from public advisory classes rather than from what the engine can do,
  but it is still our suite. A suite written by the Semgrep team would look
  different.
- The Semgrep rule pack is hand-written by us. An expert could very likely do
  better, particularly on the `match`/`enum` misses. The AJAX gap is structural
  and would survive a better author; the rest might not.
- Psalm is being run without a WordPress taint plugin because none exists. With
  one, its SQL injection score would not be zero. That absence is a real fact
  about using Psalm on WordPress today, not a rigged setup, but it is a fact
  about the ecosystem rather than about Psalm.
- Both competitors ran with zero project-specific tuning, as did wp-taint.

**Where the comparison genuinely favours wp-taint** is narrower than the
headline numbers suggest: a WordPress-specific catalogue, structural rules for
the authorization classes taint cannot reach, and interprocedural summaries that
credit a sanitiser applied inside a callee. Those three account for essentially
the whole gap.

## Performance

Measured per plugin on the WordPress.org top fifty. Analysis is whole-program,
so a plugin is the unit.

| Plugin | Files | Lines | Time | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| akismet | 29 | 7,678 | 1.2s | 67 MB |
| advanced-custom-fields | 290 | 83,330 | 12.9s | 417 MB |
| duplicator | 691 | 110,789 | 15.6s | 371 MB |
| all-in-one-seo-pack | 519 | 162,497 | 16.4s | 445 MB |
| wordpress-seo | 1,682 | 209,674 | 25.1s | 584 MB |
| google-site-kit | 1,859 | 252,762 | 34.9s | 805 MB |
| wpforms-lite | 3,990 | 670,988 | 66.8s | 1,390 MB |
| woocommerce | 4,025 | 786,566 | 157.8s | 2,310 MB |

The target was 50k lines in under 60 seconds single-threaded. Across the whole
corpus that works out at roughly **7 seconds per 50k lines**, comfortably inside
it.

`--jobs` forks after parsing, so children inherit the parsed CFGs through
copy-on-write. Parsing stays serial, which caps the speedup well short of
linear:

| Plugin | `--jobs=1` | `--jobs=4` | `--jobs=8` |
| --- | ---: | ---: | ---: |
| wordpress-seo (210k lines) | 29.6s | 14.6s | 13.3s |

Output is byte-identical at every job count, which
`tests/Feature/ParallelTest.php` asserts rather than assumes.

The result cache is keyed on every input — tool version, resolved catalogue,
analysis options and the content of every file — so an unchanged re-scan costs
almost nothing:

| | Cold | Warm |
| --- | ---: | ---: |
| duplicator (111k lines) | 15.6s | 0.18s |

Because analysis is whole-program, changing one file invalidates the whole
cache. Anything finer would be unsound: a file's findings depend on functions
declared in other files.

Memory is the real constraint, not time. Interprocedural taint crosses files, so
every parsed file is live at once, and it scales with the tree rather than with
the largest file. WooCommerce needs about 2.3 GB — above the 2 GB default
`bin/wp-taint` sets, so a tree that size needs
`WP_TAINT_MEMORY_LIMIT=4G`. That is noted in `KNOWN_LIMITATIONS.md`.

## Reproducing

```bash
composer corpus:fetch                      # ~50 plugins from WordPress.org

# wp-taint
vendor/bin/wp-taint scan tests/Fixtures/vulnerable --format=json --fail-on=never

# Semgrep
semgrep --config docs/benchmark-semgrep-rules.yml tests/Fixtures

# Psalm
composer require --dev vimeo/psalm php-stubs/wordpress-stubs
vendor/bin/psalm --taint-analysis
```
