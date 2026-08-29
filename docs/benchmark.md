# Benchmark

wp-taint against the two tools it would actually be chosen over, on the same
fixture suite.

Run on macOS 15 (arm64), PHP 8.3.32, against Semgrep 1.174.0 and Psalm 6.16.1.
184 fixtures: 92 vulnerable, 92 safe.

> **Note**
> This is a point-in-time comparison against the suite as it stood when the
> three tools were run together. The regression suite has grown since (226
> fixtures today) and these numbers are not re-measured on every change, because
> doing so means re-running two external tools. The wp-taint half is covered
> continuously by `composer test`; the comparison is a snapshot.

## Read the middle column, not the first

| | wp-taint | Semgrep | Psalm |
| --- | --- | --- | --- |
| **All 184 fixtures** | **92 / 92** caught, **0** FP | 67 / 92, 15 FP | 38 / 92, 1 FP |
| **The original 147** | **69 / 69** caught, **0** FP | 64 / 69, 12 FP | 33 / 69, 0 FP |
| The 37 added later | 23 / 23, 0 FP | 3 / 23, 3 FP | 5 / 23, 1 FP |
| Time on the tree | **0.5s** | 2.3s | 3.7s |
| Configuration | none | hand-written 13-rule pack | `php-stubs/wordpress-stubs` |

**The first row overstates the gap and should not be quoted on its own.**

147 of these fixtures were written before this engine could do most of what it
now does. The other 37 were added while fixing bugs the corpus exposed, and each
one pins a shape the fixing work had just taught wp-taint to handle: dynamic
calls, hook dispatch, include scope, by-reference writes, per-key array taint.
Semgrep gets 3 of 23 on them not because it is bad, but because they are a
catalogue of things its analysis model does not attempt.

So the honest comparative number is the middle row: **on the suite that predates
this work, Semgrep finds 93% of the vulnerable fixtures.** It is a capable tool.
What separates the results there is the safe half.

## The safe half is the half that matters

A tool that cries wolf gets muted and then deleted, at which point its true
positives stop counting.

On the original 147, Semgrep reports 12 false positives against wp-taint's 0.
They cluster in one place — a value that *was* escaped, by a route Semgrep's
intra-file taint mode cannot follow:

```php
$safe = array_map( 'esc_html', $_GET['items'] );   // reported
echo implode( ', ', $safe );

$slug = preg_replace( '/[^a-z0-9_-]/', '', $_GET['slug'] );   // reported
echo $slug;

$wpdb->prepare( "SELECT … FROM {$wpdb->prefix}items WHERE id = %d", $id );   // reported
```

Every one of those is a sanitizer wp-taint models and Semgrep's rule pack cannot
express: an escaper applied through `array_map()`, an allowlist regex, a
`$wpdb` table identifier that is not data.

## Where each tool's gaps actually are

Not all misses are the same kind of miss, and the distinction decides whether a
gap is fixable by its maintainers or structural.

### Semgrep — 64/69 on the original suite, 12 false positives

**Its model is intra-file taint.** That is a deliberate design point in the OSS
engine, and it is the whole explanation for the 37-fixture column: by-reference
writes (6 missed), dynamic calls (4), hook dispatch (4), per-key arrays (3). None
of that is reachable without cross-function summaries.

**Its rule pack is hand-written, and that is the fair way to run it.** The 13
rules in `docs/benchmark-semgrep-rules.yml` use Semgrep's own taint mode with the
same sources, sanitizers and sinks as `registries/wordpress.toml`. A commercial
Semgrep WordPress pack may well do better; this measures what a competent
engineer gets in an afternoon.

### Psalm — 33/69 on the original suite, 0 false positives

Psalm has a real interprocedural taint engine and, where it fires, it is
precise: zero false positives on the original 147. Two things stop it.

**It misses every SQL injection (13).** Psalm's taint model has no idea what
`$wpdb` is. `php-stubs/wordpress-stubs` declares the class, but nothing marks
`wpdb::query()` as a sink or `wpdb::prepare()` as a sanitizer, so every
`$wpdb->query( "… {$_GET['x']} …" )` passes silently. **That is a catalogue gap,
not an engine one** — a Psalm plugin nobody has written would close it.

**It misses every authorization bug (11).** Expected, and not a criticism: a
missing `permission_callback` has no source and no sink. Taint analysis
structurally cannot find it, which is exactly why wp-taint carries structural
rules alongside the dataflow engine.

Strip those two classes and Psalm is a much closer competitor than the headline
implies.

## What this comparison is not

**The fixtures are ours.** They were written by the same people who wrote the
engine, and 37 of them were written *after* the behaviour they test. A suite
authored alongside a tool will flatter that tool, and no amount of care fully
removes that. The original/added split above is there so the effect is visible
rather than blended away.

**184 single-file cases are not a codebase.** The evidence that is not
self-scored is the corpus: 50 real plugins from WordPress.org, 21,148 files and
4.1 million lines, currently 1,326 findings and zero convergence warnings across
every one of them, with a dozen false
positive classes found and fixed at the root — each one recorded in
[tuning.md](tuning.md) with the plugin that exposed it. Eight of those plugins
are pinned by version and their counts are checked in CI, so a change that moves
them has to say so.

**A false positive rate under 10% on the corpus has not been demonstrated.**
That gate needs a finding-by-finding triage with a verdict on each, which is a
human job and remains outstanding.

## Methodology

Each fixture is analysed **on its own**. That matters: `acme_render` is defined
in eight different fixtures, so analysing the suite as one program lets a safe
fixture's helper bind to an unescaped definition in a vulnerable one. Scanned
together, wp-taint scores 87/92 with 6 false positives — an artefact of the test
data, and one that penalises exactly the two tools with cross-file analysis.

Fixtures are copied outside `tests/` before scanning, because Semgrep's default
`.semgrepignore` excludes `tests/` and silently reports zero findings on 184
skipped files. An earlier version of this document told you to run it against
`tests/Fixtures`, which would have produced a meaningless zero.

A tool is scored as catching a fixture if it reports **any** finding in a
vulnerable file, and as a false positive if it reports any finding in a safe
one. This is generous to the competition — it does not check that the finding is
the right one, on the right line, of the right class.

## Reproducing

```bash
# Fixtures, copied outside tests/ so Semgrep will look at them
mkdir -p /tmp/bench && cp -r tests/Fixtures/vulnerable tests/Fixtures/safe /tmp/bench/
rm -f /tmp/bench/*/*.expected.json

# wp-taint
vendor/bin/wp-taint scan /tmp/bench --format=json --fail-on=never

# Semgrep — --no-git-ignore is required, see Methodology
semgrep --config docs/benchmark-semgrep-rules.yml /tmp/bench --json --no-git-ignore

# Psalm
composer require --dev vimeo/psalm php-stubs/wordpress-stubs
vendor/bin/psalm --config=psalm-benchmark.xml --taint-analysis
```

Scored per file rather than per tree; see Methodology for why.
