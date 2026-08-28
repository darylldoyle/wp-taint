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
  Run with --verbose for the full path.
─────────────────────────────────────────────────────────────
  0 critical   1 high   0 medium   0 low
  1 finding in 1 file · 18 files scanned · 0.2s
─────────────────────────────────────────────────────────────

  Why is a value tainted? Ask about the line:
  wp-taint explain ./src/includes/class-report-renderer.php:47 --scope=./src
```

`explain` is a command, not a scan flag, and `--scope` is not optional: without
it the file is analysed alone, and anything whose taint arrives through an
include or a hook comes back clean.

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
- Escaping undone before output — a value escaped and then passed through a
  filter, or through one of the 629 core functions that return a filtered value
- SQL injection, including `$wpdb->prepare()` called with a non-literal format
  string, and `esc_sql()` used where there are no quotes for it to escape
- Local file inclusion, arbitrary file read and write
- Command injection and `eval()`
- PHP object injection through `unserialize()`, including from stored data —
  reported separately, because that one needs an attacker who can write the
  option or meta first
- Open redirects and HTTP header injection

Calls are followed through the value that names them: a callable in a variable,
`call_user_func()`, `array_map()`, and hook dispatch. A callback registered with
`add_filter()` that reads `$_GET` taints the filter's result at every
`apply_filters()` site; one that escapes is credited.

Writes that go back through an argument are followed too — `preg_match()` into
`$matches`, `parse_str()` into an array, a user function's `&$out` parameter, and
the aliases created by `$a = &$b` and by-reference `foreach`.

And `include`/`require` join the two files' scopes, so the theme shape works:
`$title = $_GET['title']; include 'header.php';` connects to the template that
echoes it. Paths fold from `__DIR__`, constants, and the pure path helpers
WordPress builds them with. `--no-follow-includes` turns it off.

**Broken authorization**, via structural rules, which taint analysis
structurally cannot find:

- `register_rest_route()` with no `permission_callback`
- `permission_callback => '__return_true'` on a route that writes
- `permission_callback` that resolves but reaches no authorization check
- `wp_ajax_*` handlers with no capability check and no nonce check
- `admin_post_*` handlers with no capability check — a nonce is not one
- A guard that redirects without `exit`, so the code it guards runs anyway
- A nonce created or verified with no action, so it is the shared `-1` token
- A nonce check behind `isset()` on the same parameter, which omitting it skips
- `update_option()` whose option *name* comes from the request, which is
  privilege escalation rather than stored data

These walk the call graph rather than matching names, so a check delegated to a
helper counts and a helper merely *named* like a check does not. A nonce is
recorded as proving intent rather than entitlement, which is why it satisfies
the AJAX rule and not the admin-post one.

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
  --dynamic-calls=POLICY           clean | propagate (default) | tainted
  --no-follow-includes
  --include-path=PATH              analyse for symbols, never report (repeatable)
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
*abandoned* — a call it could not resolve — rather than proved clean.
`--dynamic-calls=tainted` then gives an upper bound on what might be missing,
which is what you want when auditing the auditor. `--dynamic-calls=clean` is the
other end: no assumptions, and a documented false negative wherever the engine
lost the thread. See KNOWN_LIMITATIONS.md § dynamic calls.

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

Stored sources — `get_option()`, `get_post_meta()` and friends — are on by
default, because stored XSS is most of the WordPress CVE population.
`--no-stored-taint` turns them off if you want to triage reflected issues
first.

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

## Scored against real CVEs, both sides of the fix

47 published CVEs across 24 WordPress.org plugins, each pinned to the last
vulnerable release *and* the release that fixed it. Scanning both is what makes
it sharp: a finding that disappears when the bug is fixed is attributable in a
way that a finding in a known-vulnerable plugin is not.

```bash
composer cve:fetch
composer cve:check
```

**9 attributed · 18 reported but not attributable · 20 silent.**

Three outcomes rather than two, because plenty of real fixes do not remove the
flow. CVE-2022-2593 in Better Search Replace is SQL injection through
unvalidated table names; we report `'DESCRIBE ' . $table` in both releases, and
the fix is `array_map( 'trim', ... )`. Scoring that a miss understates the
engine as badly as scoring it a hit would flatter it — so it is counted apart
and never added to the headline.

Where it fails, by class:

| | attributed | reported | silent |
| --- | --- | --- | --- |
| Code injection (CWE-94) | 0 | 1 | **4** |
| Deserialization (CWE-502) | 1 | 0 | 2 |
| Open redirect (CWE-601) | 0 | 0 | **3** |
| XSS (CWE-79) | 3 | 6 | 3 |
| Authorization (CWE-862/863) | 2 | 5 | 5 |
| Path traversal (CWE-22) | 1 | 4 | 0 |
| SQL injection (CWE-89) | 1 | 2 | 2 |
| SSRF (CWE-918) | 1 | 0 | 1 |

Deserialization was a zero until this benchmark said so: stored data did not
carry object-injection taint, on reasoning that holds for filesystem and URL
sinks and not for this one. Fixing it caught CVE-2023-1196 in Advanced Custom
Fields.

The CWE-94 cases are plugins whose purpose is executing admin-supplied code, so
those CVEs are privilege-boundary bugs wearing a code-injection label, and the
open-redirect three turned out not to be `wp_redirect()` flows at all. Both are
worth knowing before reading the column as a verdict on the rules.

**"Attributed" is evidence, not proof.** A finding can vanish because the fix
refactored the line rather than because it was the bug. This is the sharpest
measurement here and it is still not a confirmed hit.

## Scored against an answer key we did not write

The fixture suite is ours, and 37 of its cases were written after the behaviour
they test. The corpus is third-party code with no ground truth. Both flatter
this tool in the same place.

The WordPress plugin review team published an
[intentionally vulnerable plugin](https://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/)
in 2013 to teach plugin authors what their code does wrong, and a
[companion post](https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/)
enumerating every flaw in it. Somebody else's test, somebody else's answer key,
written for a purpose unrelated to this tool.

**It finds all 12.** Three of them — the CSRF and control-flow bugs — the taint
engine cannot see at all, and are caught by structural rules; filing them under
"not a dataflow problem" would have been the easy way out.

```bash
composer vulnerable:fetch
composer vulnerable:check
```

The score is committed in `tests/Fixtures/vulnerable-plugin-truth.json` and
checked in CI. It fails in both directions: a caught issue going quiet is a
regression, and a missed one starting to fire means somebody fixed something
without noticing and the file is now lying about where the tool stands.

## How it compares

Against the same fixture suite, each fixture analysed on its own, with no
project-specific tuning for anyone:

| | wp-taint | Semgrep 1.174 | Psalm 6.16 |
| --- | --- | --- | --- |
| Vulnerable caught, all 184 | **92 / 92** | 67 / 92 | 38 / 92 |
| Vulnerable caught, original 147 | **69 / 69** | 64 / 69 | 33 / 69 |
| False positives, original 147 | **0 / 78** | 12 / 78 | 0 / 78 |

**Quote the second row, not the first.** 37 of these fixtures were added while
fixing bugs the corpus exposed, and each pins a shape that work had just taught
this engine to handle — dynamic calls, hook dispatch, include scope,
by-reference writes. Semgrep gets 3 of 23 on them because they are a catalogue
of what its analysis model does not attempt. On the suite that predates the
work, it finds 93% of the vulnerable fixtures. It is a capable tool.

What separates them there is the safe half: 12 false positives against zero,
clustered on values that *were* escaped by a route Semgrep cannot follow — an
escaper applied through `array_map()`, an allowlist regex, a `$wpdb` table
identifier that is not data.

Psalm is precise where it fires — zero false positives — and misses every SQL
injection because nothing tells it what `$wpdb` is, which is a catalogue gap a
plugin would close, and every authorization bug because those have no source and
no sink, which taint analysis structurally cannot find.

Full working, including what the comparison does not prove and why the fixtures
flatter us, in [docs/benchmark.md](docs/benchmark.md).

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
