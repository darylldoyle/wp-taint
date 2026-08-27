# wp-taint

Interprocedural taint analysis for WordPress PHP. Finds real XSS, SQL injection
and broken authorization, with a source-to-sink trace on every finding.

```bash
composer require --dev enshrined/wp-taint
vendor/bin/wp-taint scan ./src
```

```
HIGH      wp.xss.unescaped-output
  includes/class-report-renderer.php:47:10  echo $this->build_header( $filter );

    source    :42:24  $filter = wp_unslash( $_GET['report_filter'] );
    sink      :47:10  echo $this->build_header( $filter );

  Untrusted input reaches output without HTML escaping.
  Run with --verbose for the full path, or --explain for why.
```

## Why this exists

Every existing option fails on WordPress in a specific way.

| Tool | Where it falls down on WP |
| --- | --- |
| Psalm taint analysis | Precision depends on type inference. Plugin code is untyped array soup, so inference degrades and the taint graph degrades with it. Also needs a coherent autoloader, which themes do not have. |
| Semgrep / Opengrep | Ignores types, which suits WP, but cross-function taint is limited to a single file. Interfile taint is roadmap, not shipped. |
| PHPStan | No dataflow engine. Taint would have to be rebuilt on collectors, fighting per-file caching and parallelism. |
| WPCS sniffs | Encode the right catalogue of escapers and sinks, but are token-based and intraprocedural, so they are noisy and miss anything crossing a function boundary. |

wp-taint takes the SSA/CFG approach — which gives interprocedural taint cheaply
— and the WPCS catalogue, which is the expensive, already-curated asset.

## What it finds

**Injection**, via dataflow from source to sink:

- Reflected and stored XSS, including across one or more function boundaries
- SQL injection, including `$wpdb->prepare()` called with a non-literal format string
- Local file inclusion, arbitrary file read and write
- Command injection, `eval()`, and PHP object injection through `unserialize()`
- Open redirects and HTTP header injection

**Broken authorization**, via structural rules, which taint analysis
structurally cannot find:

- `register_rest_route()` with no `permission_callback`
- `permission_callback => '__return_true'` on a route that writes
- `wp_ajax_*` handlers with no capability check and no nonce check

## Taint is never a boolean

`esc_html()` clears HTML taint and does nothing whatsoever for SQL.
`$wpdb->prepare()` clears SQL and nothing else. `esc_url_raw()` is for redirects
and database storage, not for HTML.

Every value carries a *set* of taint kinds, and every sanitizer clears a
specific subset. That is the single most important modelling decision in the
project, and it is why this reports the SQL injection in:

```php
$slug = esc_html( $_GET['slug'] );
$wpdb->query( "SELECT * FROM wp_items WHERE slug = '{$slug}'" );
```

…while reporting nothing at all in:

```php
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items WHERE slug = %s", $_GET['slug'] ) );
```

## Usage

```
wp-taint scan <paths...>
  --registry=NAME|PATH             default: wordpress (also: php-core, wordpress-vip)
  --config=PATH                    default: ./wp-taint.toml if present
  --format=console|json|sarif      default: console
  --output=PATH                    default: stdout
  --baseline=PATH
  --generate-baseline[=PATH]
  --min-severity=low|medium|high|critical
  --fail-on=SEVERITY               default: high; "never" to disable
  --no-interprocedural
  --no-stored-taint
  --stored-taint-writes
  --no-structural-rules
  --assume-dynamic-tainted
  --exclude=GLOB                   repeatable
  --jobs=N                         worker processes (default 1; needs pcntl)
  --parse-report
  --dump-taint-graph=PATH
  --trace-full
  --no-cache  --cache-dir=PATH
  -v                               full trace on every finding

wp-taint explain <file>:<line> [--kind=html|sql|...] [--scope=DIR]
wp-taint dump-cfg <file> [--format=text|dot] [--show-lowering]
wp-taint registry:dump [--registry=NAME] [--format=text|json]
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` execution
error — **including any file that failed to parse**. A file the scanner could
not read is a file it could not clear, and a green build over an unread file is
a lie.

### Handing results to an agent

Use `--format=json`. Console output is lossy by design: colour codes, collapsed
traces, truncated spans. The JSON carries the full trace, the taint kinds at
every step, and the rule definition inline on each finding, so a reader coming
to it cold needs no other context.

```bash
wp-taint scan ./src --format=json --output=findings.json
```

### Why was this *not* flagged?

The failure mode a security scanner most needs to defend against is silence.
`explain` turns "I don't trust it" into a specific, checkable statement:

```bash
wp-taint explain includes/class-report-renderer.php:58 --kind=html
```

```
includes/class-report-renderer.php:58

  return '<h2>' . $label . '</h2>';

  Taint at this point: (none)

  Why:
    - sanitize: esc_html() clears html. (none) survives.
```

The important case is the third one, where the engine says a path was
*abandoned* — a dynamic call it could not resolve — rather than proved clean.
`--assume-dynamic-tainted` then gives an upper bound on what might be missing,
which is what you want when auditing the auditor.

## Suppressing findings

Inline, with a mandatory reason:

```php
// wp-taint-ignore-next-line wp.xss.unescaped-output -- output is admin-only, reviewed 2026-08
echo $markup;
```

A suppression without a reason is reported as an error of its own: "someone
silenced this and nobody knows why" is a worse state than the original finding.

Or by baseline, for adopting the tool on an existing codebase:

```bash
wp-taint scan ./src --generate-baseline
wp-taint scan ./src --baseline=wp-taint-baseline.json
```

Fingerprints deliberately exclude the line number, so a baseline survives
unrelated edits above a finding. The suppressed count is always printed, so the
debt stays visible.

## The catalogue is data

Sources, sinks, sanitizers and propagators live in `registries/*.toml`. Adding a
WordPress escaper never requires a code change.

```toml
[[sanitizers]]
function = "esc_attr"
clears = ["html", "html_attr"]

[[propagators]]
function = "wp_unslash"
note = "Strips slashes only. Pure pass-through. NOT a sanitizer."
```

A project-local `wp-taint.toml` in the scan root is loaded last and can add or
override anything. Unknown keys are a hard error, not a warning: a typo in a
security catalogue silently creates false negatives.

Read the resolved catalogue with `wp-taint registry:dump`.

## Design principles

1. **Deterministic.** Same input, byte-identical output. Findings sorted by
   file, line, column, rule id. No randomness, no hash-order iteration, no
   timestamps in machine-readable output.
2. **Fail loudly, never silently.** A file that fails to parse is a reported
   error, not a skipped file.
3. **Structure carries the value.** The catalogue is data, not code.
4. **False positives are the product risk.** A tool that cries wolf gets muted
   and then deleted. When in doubt, take the documented false negative.
5. **No LLM, no network, no telemetry on the analysis path.** Fully
   deterministic and offline. The only thing that touches the network is
   `tools/fetch-corpus.php`, a developer tool.

## Speed

A plugin is the unit: interprocedural taint crosses files, so the whole scan is
parsed and held in memory at once.

| Plugin | Lines | Time | Peak RSS |
| --- | ---: | ---: | ---: |
| akismet | 7,678 | 1.2s | 67 MB |
| advanced-custom-fields | 83,330 | 12.9s | 417 MB |
| wordpress-seo | 209,674 | 25.1s | 584 MB |
| woocommerce | 786,566 | 157.8s | 2,310 MB |

Roughly 7 seconds per 50k lines single-threaded. `--jobs=4` roughly halves that
— parsing stays serial, so it is not linear — and produces byte-identical
output, which is enforced by a test rather than hoped for.

The result cache is keyed on every input, so an unchanged re-scan is close to
instant (15.6s to 0.18s on Duplicator). Because the analysis is whole-program,
changing one file invalidates the whole cache; anything finer would be unsound.

Memory is the real constraint. `bin/wp-taint` raises the limit to 2 GB, which
covers everything in the WordPress.org top fifty except WooCommerce; for a tree
that size set `WP_TAINT_MEMORY_LIMIT=4G`.

## How it compares

Against the same fixture suite, with no project-specific tuning for anyone:

| | wp-taint | Semgrep 1.174 | Psalm 6.16 |
| --- | --- | --- | --- |
| Vulnerable caught | **69 / 69** | 64 / 68 | 31 / 68 |
| False positives | **0 / 78** | 9 / 73 | 4 / 73 |

Psalm misses every SQL injection because nothing tells it what `$wpdb` is, and
every authorization bug because those have no source and no sink. Semgrep does
much better, and its remaining gaps are structural: a rule matches one AST node,
so it cannot see an `add_action()` registration and the handler body at once.

Both tools' false positives are the same shape — a sanitiser applied inside a
callee — which is precisely what function summaries exist to credit.

Full working, including where the comparison is unfair to wp-taint, in
[docs/benchmark.md](docs/benchmark.md).

## Where it is imprecise

Honestly, in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). Findings that
crossed something the engine could not resolve carry `imprecise: true` so you
can filter on it.

## Development

```bash
composer install
composer test        # Pest
composer analyse     # PHPStan, level max + strict rules
composer lint        # PHP_CodeSniffer, PSR-12 + Slevomat
composer check       # all three
```

The fixture suite in `tests/Fixtures/` is the regression net: ~70 vulnerable
files and ~75 safe ones that are superficially similar. The safe half matters
more — a single false positive there fails the build.

Expectations are written as inline `// wp-taint-expect <rule-id> <kind>`
annotations on the sink line and generated into `.expected.json` siblings by
`composer fixtures:build`. CI fails if the two drift apart.

```bash
composer corpus:fetch    # ~50 plugins from WordPress.org, gitignored
vendor/bin/wp-taint scan tests/Fixtures/corpus --parse-report
```

## Requirements

PHP 8.2 or newer. No WordPress installation needed — the tool analyses source,
it does not run it.

## Licence

MIT.
