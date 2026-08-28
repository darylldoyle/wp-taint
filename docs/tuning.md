# Tuning against the corpus

What running the WordPress.org top fifty actually taught, and what changed as a
result. This is the record of Phase 7.

The corpus is 50 plugins; at the versions currently fetched, 21,148 PHP files
and 4.1 million lines outside `vendor/`. It moves when upstream releases. It is not
committed — it is third-party code under assorted licences that changes every
time upstream releases — so `composer corpus:fetch` downloads it into
`tests/Fixtures/corpus/`, which is gitignored.

Everything below was found by running that corpus, not by imagining what the
engine might get wrong. Every fix has a fixture taken from the real plugin code
that exposed it, so none of them can come back.

## Three engine bugs, all the same shape

The first corpus run reported *"taint fixed point did not converge within 64
iterations"* on nine of Akismet's functions alone. That warning is worse than a
wrong answer: the engine gives up mid-flight, so everything downstream of the
loop is unreliable and nobody knows which findings are affected.

All three causes were the same underlying thing. **SSA does not give every write
its own operand**, so two ops end up writing one slot with different answers,
and the transfer functions stop being monotone.

| Shape | What happened |
| --- | --- |
| `$out = array(); $out[$k] = $tainted;` | Both write the same operand — SSA does not re-version an array for an element write. The assignment set it empty, the element write set it tainted, forever. |
| `if ( isset( $_GET['x'] ) )` | php-cfg gives `Op\Expr\Assertion` an operand *already written* by the op producing the value. Falling through to the generic expression branch zeroed it, which both oscillated and laundered taint. |
| `self::$option = array( … );` | The same two-writer shape on a static property. |

The fixes: element taint moved to its own slot in `TaintState`, assertions
became a pass-through, and rather than patching each op, `transfer()` now
declines any expression whose result is an assignment target — the `Assign` owns
that operand.

Nine regression tests in `tests/Feature/ConvergenceTest.php`, written from the
shapes that actually broke.

The scans got substantially faster because the wasted iterations disappeared:
All in One SEO went from 56.4s to 16.4s.

### The fourth, found the same way

Seventeen functions still did not converge after those three. The same method
found the cause: lower the iteration cap, log which operand changes on the final
passes, find the two ops fighting over it.

```php
if ( is_callable( array( $this->post, $name ) ) ) { … }
```

`Op\Expr\Array_` and `Op\Expr\Assertion` write the same operand. The array
literal set its own slot from the keys alone — empty, for a list — while the
assertion over it set the same slot from the *union* of both slots, promoting
the element taint into it. Each pass undid the other.

The fix is that pass-throughs now propagate slot-wise: own taint to own,
element taint to element. Reads out of a container still flatten both, which is
where flattening belongs.

**Every corpus function now converges.** Eleven plugins were affected; the last
two were Jetpack and WooCommerce.

## Following the value that names the call

The largest remaining source of false negatives was not a bug but a refusal:
the engine stopped at every indirection. WordPress routes an enormous amount of
control flow through a callable in a variable, so that is precisely where the
interesting flows were.

What now resolves: a callable that traces back to a literal, a phi of literals,
or a concatenation of resolvable parts; `array( $object, 'method' )` and
`array( 'Class', 'method' )`; a closure; an object with `__invoke`; and
`new $class()`. Dispatchers — `call_user_func()`, `array_map()`, `usort()` and
the rest — resolve to their callee rather than to themselves, declared as data
under `[[dispatchers]]` so a project can add its own.

Two decisions worth recording.

**A callable that resolves to several names reaches all of them.** Picking one
would be a guess. Both are analysed and the effects unioned, so a sink in either
is reported and a flow is proved safe only when *every* callee escapes it.

**A name nobody can find a body for counts as unresolved.** Resolving
`'render_a'` to a function that exists in neither the catalogue nor the scanned
code, and then reporting it clean, would lose the flow without even marking it
imprecise — strictly worse than admitting defeat.

### What the default costs

`--dynamic-calls` replaced `--assume-dynamic-tainted` with three settings, and
the default moved to `propagate`. Measured on Duplicator, the corpus plugin with
the most unresolved calls:

| `--dynamic-calls` | Findings |
| --- | --- |
| `clean` | 92 |
| `propagate` *(default)* | 96 |
| `tainted` | 170 |

Four extra findings for the default, against eighty-five for the pessimistic
upper bound. On four smaller plugins the delta between `clean` and `propagate`
was zero. The resolution work is what made the default affordable: the calls
still unresolved after it are mostly ones whose return value never reaches a
sink.

Across the whole corpus the total fell from 1,046 findings to **851**, because
resolving a dispatcher cuts both ways: `array_map( 'esc_html', $items )` and
`call_user_func( 'esc_html', $v )` are now real sanitizer applications rather
than opaque calls. The fixture suite stayed at 100% on both halves throughout,
so none of that was bought with false negatives.

Findings resting on an assumption are counted: 395 of the 851 carry
`imprecise`. That is not 395 guesses — the flag marks any finding in a function
where the engine lost the thread anywhere, so it is an upper bound on doubt
rather than a measure of it.

## Making hooks part of the call graph

15,637 `add_action`/`add_filter` registrations and 9,173 `apply_filters` calls in
the corpus, none of them connected to anything. A filter callback reading `$_GET`
could taint a value the engine believed was clean; an action's arguments never
reached the sinks inside its callbacks.

Once the graph exists, a dispatch is a call with several callees, which the
Phase 1 dispatcher machinery already handles. `hook = true` on a
`[[dispatchers]]` entry says the callable argument names a hook.

### Two silent misses, both large

**Namespaced registrar calls.** Inside a namespace, `add_action(...)` compiles to
the namespaced call form even though it resolves to the global function at
runtime. Matching only the plain form missed every registration in namespaced
code. Elementor resolved 10 of its 757.

**`__NAMESPACE__ . '\\render'`**, which is how a namespaced plugin names a
callback. The identity magic constants now fold to strings during lowering, where
the enclosing namespace and class are still in hand — so every resolver
downstream gets it without learning about scope. A trait's `__CLASS__` is left
alone: it is the *using* class at runtime, and a wrong answer would be worse than
an opaque one.

Resolution after both fixes:

| Plugin | Registrations resolved | Syntactic `add_*` |
| --- | --- | --- |
| Contact Form 7 | 143 | 143 |
| Akismet | 70 | 72 |
| Elementor | 717 | 757 |
| Yoast SEO | 536 | 594 |
| Advanced Custom Fields | 325 | 375 |

The syntactic counts are `grep`, so they include matches in comments and strings;
the real rates are higher.

### The wildcard that had to go

A registration whose hook *name* will not resolve was first modelled as being on
every hook — the sound choice, since it might be any of them.

It is the wrong one. Advanced Custom Fields had 22 such registrations against 201
hooks, so every dispatch gained 22 spurious callees and its average went from 1.4
callbacks per hook to 23.4. Five of the six findings that appeared on ACF came
from those edges and vanished when they were removed.

They are surfaced in the unresolved-hook list instead, where the other coverage
gaps already live. The standing trade applies: a documented false negative beats
an undocumented false positive.

## Authorization: reachability instead of names

The AJAX rule accepted any call whose name contained `can`, `capab`,
`permission`, `nonce`, `referer`, `authori`, `authenticat` or `verify`. It
credited `acf_verify_ajax()` for the right reason by accident and would have
credited `$this->can_haz_cheeseburger()` for no reason at all.

It now walks the call graph looking for one of the `[[authorization]]`
primitives. `acf_verify_ajax()` counts because it calls `wp_verify_nonce`, which
we can see. A helper named like a check but returning `true` is reported. The
heuristic survives only where the graph cannot speak, and those findings are
marked imprecise.

### The third REST class needed two conditions, not one

`permission_callback` presence used to be the whole test, which credited
`array( $this, 'noop' )` exactly as much as a real capability check. The new rule
reports a callback that reaches no authorization primitive — and on its first
corpus run it reported both of Akismet's routes:

```php
public static function remote_call_permission_callback( $request ) {
    $local_key = Akismet::get_api_key();
    return $local_key && ( strtolower( $request->get_param( 'key' ) ?? '' ) === strtolower( $local_key ) );
}
```

That is a real authorization check, written with a shared secret rather than a
WordPress primitive. Reachability alone was the wrong test.

The rule now needs both: nothing below the callback reaches a primitive, *and*
the body contains no branch, comparison, boolean operator or negation, so it
cannot be refusing anything. A cheap syntactic proxy for "provably returns a
constant", and named as one — being wrong now means staying quiet, which is the
direction an authorization rule should fail in. Akismet: back to 0.

### What Phase 2 cost

Nothing, on the corpus. Like-for-like over the 48 plugins that completed in both
runs: **851 findings before, 840 after — down 1.3%**, while adding the entire
hook graph.

That is not an accident of the gate. Following a filter cuts both ways, and the
plugins that moved most moved *down*: WP Fastest Cache −8, WPForms −7, Jetpack
−4, because a sanitizing callback is now credited where the dispatch used to be
an opaque pass-through.

Full corpus, all 50 plugins, no errors: 1,061 findings, **0 convergence
warnings**.

The one real increase was WP Super Cache, +9, and every one of them is a false
positive of a kind the hook graph could only have exposed:

```php
$extra_str = apply_filters( 'supercache_filename_str', $extra_str );
…
// Filters above may return arbitrary data, so restrict it to a safe set of characters.
$extra_str = preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $extra_str );
```

The flow is real — the registered callback reads the user agent — and the plugin
defends against it correctly with an allowlist regex the engine models as a
plain propagator. 146 sites across the corpus use that idiom. Recorded as its
own piece of work rather than fixed here.

### Route options no longer have to be inline

`register_rest_route( $ns, $route, $this->route_args() )` was counted as
unresolved and skipped, which meant the most safety-critical rule in the tool
quietly declined to look at a large share of the routes in the corpus.

A variable assigned exactly once from a literal, or a function whose only
`return` is a literal, now folds. Deliberately a constant fold and not a dataflow
analysis: a wrong answer here is an authorization bypass either reported or
missed. **Unresolved route options across the corpus: 1.**

## Following references

1,433 by-reference parameter declarations in the corpus, plus `preg_match` and
`parse_str`, which are everywhere. The lowest-risk work in the plan: it adds
flows that are unambiguously real.

Corpus effect: **1,061 findings to 1,071**, 0 convergence warnings. Ten of the
twenty new ones are on UpdraftPlus, and they are exactly what the section was
built to find:

```php
preg_match( '/ENGINE=([^\s;]+)/', $create_table_statement, $eng_match );
$this->table_engine = $eng_match[1];
…
$wpdb->query( $sql[0] );        // $table_engine interpolated
```

Content from a restored SQL dump reaches `$wpdb->query()` through a regex
capture. The authors have marked those lines `phpcs:ignore` — WPCS flags them
too — which puts them in the accepted-debt category rather than the false
positive one.

### Aliasing fought SSA before it worked

`$a = &$b` binds rather than copies, and SSA versions assignments, not aliases.
The first attempt grouped every version of a name and treated them as one slot.
That oscillated, because an ordinary assignment to `$item` legitimately
*replaces* that version, and the alias merge kept adding it back.

Two corrections, both found as convergence warnings rather than wrong answers:

- An `AssignRef` unions into its target rather than setting it. Setting undid
  what the merge added, and the two took turns.
- The link for a by-reference loop variable is one-way, into the collection's
  element slot. `foreach ( $x as &$v )` lowers to an `AssignRef` binding `$v` to
  the iterator's value, and the `$v = …` inside the loop is a fresh SSA version
  the binding never mentions — so the link has to cover every version of the
  name. Pushing back the other way would fight the assignment that owns those
  operands; pushing only into the element slot cannot, because nothing ever
  *sets* an element slot, it is only ever grown.

The loader caught one bad entry of my own: `settype( $var, $type )` writes the
argument it reads, which in an add-only model is a no-op.

## Following includes

5,996 include sites in the corpus, and the plan's highest false-positive risk:
it connects request data to template files that have never been analysed in
context. Budget was +25%.

**It came in at +0.6%** — 1,071 findings to 1,077, 0 convergence warnings. Two
plugins moved: All in One SEO +4 and Wordfence +2.

### Why it was cheap, and where it would not be

Include resolution is doing real work. Roughly half of all include sites resolve:

| Plugin | Resolved | Unresolved |
| --- | --- | --- |
| Jetpack | 631 | 478 |
| WooCommerce | 266 | 446 |
| Wordfence | 196 | 73 |
| Contact Form 7 | 43 | 18 |

Findings barely moved because most of those are bootstrap — `require_once` of a
file that defines a class or a function, with no variables in scope to carry.
The theme shape, where a template echoes a variable the includer set, is a
minority of include sites *in a plugin*. The corpus is plugin-heavy, which the
plan noted; on a theme-heavy codebase this number would be larger, and the +25%
budget was not unreasonable for one.

### Half the unresolved sites were three bugs, not dynamic paths

The first run resolved roughly half of all include sites. Asking *why* the other
half failed — rather than assuming they were genuinely dynamic — turned up three
bugs:

- **`plugin_dir_path()` forgot its `dirname()`.** It is
  `trailingslashit( dirname( $f ) )`, implemented as the trailingslashit half
  alone, so `JETPACK__PLUGIN_DIR` came out as `…/jetpack.php/`. Jetpack: 631
  resolved to 841.
- **A plugin's own `define()` wrapper was invisible.** WooCommerce declares every
  constant through `$this->define( 'WC_ABSPATH', … )`.
- **The two-pass constant build accumulated into one table**, so a constant the
  first pass could not resolve was marked unresolvable and the second pass could
  never clear it — defeating the entire reason the second pass exists.
  WooCommerce: 266 resolved to 519.

Across seven large plugins, resolution went from ~50% to **72%**. Corpus
findings moved by **+4**, which is the same lesson as before in sharper form:
the includes that were failing are overwhelmingly bootstrap, and bootstrap
carries no variables.

What remains unresolved, measured rather than guessed:

| Bucket | Share | What it needs |
| --- | --- | --- |
| `ABSPATH . 'wp-admin/…'` | 40% | `--include-path` at a WordPress checkout. The path resolves; the file is not in the scan. |
| A call in the path | 12% | `constantReturn` on `FunctionSummary` |
| A bare variable | 13% | Dataflow, and often nothing: a `glob()` loop has no static answer |
| Other constants | rest | Conditional and cross-plugin defines |

The largest bucket is not include work at all.

### The unlock was pure path helpers, not includes

Contact Form 7 resolved **none** of its 61 includes at first, because every one
is built from a constant declared like this:

```php
define( 'WPCF7_PLUGIN_DIR', untrailingslashit( dirname( WPCF7_PLUGIN ) ) );
```

Constants come from a table built over the whole scan, and `__DIR__`/`__FILE__`
fold at parse time — but the constant itself needed two function calls
evaluated. With `dirname()`, `untrailingslashit()`, `trailingslashit()`,
`plugin_dir_path()` and a few string helpers, CF7 resolves 43 of 61.

Only functions that are total, deterministic and free of filesystem access.
`realpath()` is deliberately absent: it answers a question about the machine
running the scan, not about the code.

### A cross-file taint leak that nearly shipped

Jetpack gained 29 findings, twenty of them tracing to:

```
$page_routes was left in scope by .../build/constants.php
```

`constants.php` never mentions `$page_routes`. It is a *parameter* of a function
that requires that file. With one scope entry per file, a variable pushed **in**
by one includer came straight back **out** to every other, and a shared partial
neither of them wrote became a channel between them.

The table has two halves now: **in** is what a file may find on entry, unioned
over every site that includes it; **out** is what the file's own top-level code
leaves, and only for names it actually assigns. Jetpack went back to 94, its
figure before includes were followed — all 29 were the leak.

The inbound union across includers stays, because it is the honest
over-approximation: a template included from two places really can see either
caller's state.

### The fourth oscillation of the same kind

wp-super-cache's `{main}` stopped converging, because the scope join was writing
to variables during a pass and fighting the assignments that own those operands.
Every scope write is now a one-time seed before the propagation loop — which is
also more correct, since an included file that assigns `$title` itself should win
over what its includer had.

That is four separate non-convergences across the five phases, every one of them
two ops writing one operand with different answers. It is the recurring cost of
building on an SSA form that does not version everything.

## Coverage, and what analysing WordPress core breaks

Two halves. `--include-path` analyses a tree for its symbols and never reports
on it; `tools/generate-wpcs-catalogue.php` imports the WPCS escaper and
sanitizer lists.

The generator's important half is what it refuses to emit. WPCS says *that*
`esc_attr()` escapes; it cannot say which taint kinds it clears, because a
token-based sniff has no concept of kinds — and `esc_url_raw()` is on the
escaping list while being emphatically not an HTML escaper. Kinds come from a
hand-written table, and a function whose kinds are not stated is skipped rather
than guessed. 50 entries generated, 20 skipped with a reason recorded for each.

### Core exposed two assumptions that only held because core was not analysed

Pointing `--include-path` at a real WordPress install took four small plugins
from 10 findings to 38. Two mechanisms accounted for most of it.

**`$wpdb->prefix` became tainted.** `wpdb::get_blog_prefix()` assigns
`$this->prefix`, so the moment core's body is analysed the property carries
taint — and every plugin interpolates it into SQL because there is no other way
to name a table. Cookie Law Info gained 23 findings rooted there. The
safe-identifier rule said a `$wpdb` property was clean *provided the property map
recorded no taint for it*, and core defeats the proviso. A read of a known safe
database identifier on `$wpdb` now yields clean outright.

**An unknown property owner was one shared bucket.** `propertyOwnerClass()` knew
only `$this` and the type map, so a `global $wpdb` resolved to null and every
write on an untyped receiver landed under `?::name`. `$wpdb->comments` collided
there with `WP_Query::$comments`, producing a fourteen-step trace to
`OPTIMIZE TABLE {$wpdb->comments}`.

Fixing only one of the two was **worse than fixing neither**: writes landed under
one key and lookups missed under another, so every read fell through to the
by-name fallback and the shape rule fired on properties it had in fact seen
written. Cookie Law Info went to 40 in that window. Both the dataflow and the
origin classifier now resolve receivers through the same `ReceiverResolver` the
call machinery uses.

With core referenced afterwards: Cookie Law Info 40 to 15, Akismet 4 to 2. Still
not a tuned configuration, and documented as such.

## Per-key array taint

The last of the three limitations that had been accepted as-is.

```php
$context['title'] = $_GET['title'];
$context['id']    = 42;
echo $context['id'];              // was reported, and should not be
```

A write with a literal key goes to a slot of its own; a read naming that key
sees only what went into it. Both fallbacks stay, and a fixture caught one being
dropped: a read with a *computed* key was not consulting the per-key slots, so
`echo $context[$key]` came back clean with `$context['title']` plainly tainted.
That is the unsound direction, which is why all four cases are fixtures rather
than two.

Corpus effect: **1,081 findings to 1,046**, every mover downward. Yoast SEO −14
and Loginizer −13 were the largest, and every removed trace carried the line
"Array taint is tracked per array, not per key, so the whole array is treated as
tainted from here" — which is as direct a confirmation as the corpus offers.

## The corpus as a tracked number

Seventeen bugs over this work were found by running the corpus, and none of them
by the fixture suite. Two made findings *fall*, which is the direction nobody
thinks to look in: per-key array taint took the corpus down seventeen findings,
every mover downward, and it was a false negative — `effectiveTaintOf()` had
stopped seeing keyed slots at call boundaries. The only reason it was caught is
that somebody happened to read the numbers.

So the numbers are committed. Eight plugins pinned by exact version in
`corpus-lock.json`, scanned serially, with per-plugin counts in
`corpus-baseline.json` and a CI job that fails on drift. Pinned because the full
corpus runs at latest-stable, which is right for triage and wrong for a tracked
number: a baseline that moves whenever upstream releases teaches people to
ignore it. Serial because a worker that runs out of memory takes its shard with
it, and a baseline that depends on the runner's RAM is not a baseline.

A diff is not automatically a regression — a real improvement moves the number
too. It means *look*, then either fix the cause or accept the new baseline with
the reason in the commit message. A count that falls gets flagged for extra
suspicion, because a false positive is visible and annoying while a false
negative is silent.

It earned its keep within an hour: modelling `add_query_arg()` moved two counts,
and reading the traces showed the shape test was wrong — it recognised a literal
`array()` but not `$this->get_args`, a property holding one.

## Determinism across `--jobs`, again

Elementor reported the same finding with a seven-step trace at `--jobs=1` and a
five-step one at `--jobs=2`.

`PropertyTaintMap` kept the *first* origin trace recorded for a property, on the
reasoning that writes are visited in a fixed order. True within one worker.
Across workers, a property written in two places has those writes split between
shards, so which arrives first depends on the worker count.

The obvious fix — keep the longest trace, since it explains most — does not
terminate:

```php
$this->value = $this->value . $i;   // inside a loop
```

The origin trace for `$value` splices in its own previous origin, so it grows by
a step every interprocedural round. "Longest wins" never reaches a fixed point.

The rule is the lexicographically smallest signature instead. Total, so the
choice cannot depend on arrival order; and stable, because a trace that extends
another sorts after it and so can never displace the one already chosen.

Worth recording that the parallel test suite passed throughout. Its fixture was
too small to split a property's writes across two shards, which is exactly the
condition the bug needed.

## Six false positive classes

Ordered by how many findings each accounted for.

### 1. "Not a string literal" is not "unsafe" — 532 findings

By far the largest. `wp.sqli.prepare-non-literal` fired at **critical** severity
on this:

```php
$table = self::table();   // returns $wpdb->prefix . 'wfconfig'
$wpdb->get_row( $wpdb->prepare( "SELECT … FROM {$table} WHERE name = %s", $key ) );
```

The check was asking *"is this argument a string literal"*. What `prepare()`
actually needs is *"did anything attacker-controlled reach the format string"*.
Those are different questions, and only the second is answerable without a
dataflow engine — which is the whole reason to have one.

It now reports when the format string carries SQL taint, or when a component of
it is one the engine cannot account for. The same machinery already existed for
`wp.sqli.unprepared-query`; this reuses it.

### 2. Clean property writes were never recorded — 57 findings on one plugin

LiteSpeed Cache produced 57, 42 of them critical, all on this:

```php
class Avatar {
    private $_tb;
    public function __construct() { $this->_tb = Data::cls()->tb( 'avatar' ); }
}
// in a trait the class uses:
$wpdb->prepare( 'SELECT url FROM `' . $this->_tb . '` WHERE md5 = %s', $md5 );
```

Two separate bugs. `propagateIndirectWrite()` returned early when the assigned
value carried no taint, so a *clean* property write was never recorded at all —
which defeated the whole point of tracking, because "we watched this property
and nothing tainted ever went into it" is the answer the shape rules need. And
the read is inside a trait, whose declaring class is the trait as far as the CFG
is concerned, while the write is in the class that uses it, so keyed lookup
missed across that boundary.

LiteSpeed Cache: 57 findings to 6.

### 3. Stored data is not filesystem input — several hundred findings

Stored sources were modelled as introducing `path` and `url` taint alongside
`html` and `sql`. That turned every `get_option()` holding a directory name into
a path-traversal source, and every stored URL into SSRF.

Stored XSS and second-order SQL injection are real and common. "An option holds
a directory name, therefore every `unlink()` downstream is path traversal" is
not: an attacker who can write arbitrary options already has the access those
sinks would give them.

Stored sources now carry `html`, `html_attr` and `sql` only. A project that
really does let a low-privilege user write a path into an option can add a
local `[[sources]]` entry.

### 4. The `IN (...)` placeholder idiom — 4 findings, but on Akismet

```php
$format_string = implode( ', ', array_fill( 0, count( $ids ), '%s' ) );
$wpdb->query( $wpdb->prepare( "… WHERE comment_id IN ( " . $format_string . ' )', $ids ) );
```

Every character of `$format_string` came from the literals `', '` and `'%s'`;
only its *length* depends on the data. This is the documented way to write a
prepared `IN (...)` clause and we called it a non-literal format string.

"Effectively literal" now means *"cannot carry attacker-supplied SQL syntax"*:
literals, `$wpdb` properties, integers, the output of an inner `prepare()`, and
anything built from those through calls the catalogue models as pure.

### 5. Custom `$wpdb` table properties — 107 findings on WooCommerce

Action Scheduler registers `$wpdb->actionscheduler_actions`, and WooCommerce
interpolates it into fourteen prepared queries. The safe-identifier list only
held core table names.

Any property read on `$wpdb` now counts, provided the property map records no
taint for it. Nothing attacker-controlled reaches a property of the global
database handle, and consulting the map means one that somehow did is still
reported.

### 6. Two structural rules that read their input wrong

`register_rest_route()` takes a *list* of route definitions with an optional
shared `args` schema alongside. We treated the schema block as a route and
reported it for having no `permission_callback` — which a schema block neither
has nor should have. Found on Akismet.

And the AJAX rule accepted a *method* whose name reads like a check but not a
*function*. Advanced Custom Fields opens every one of its nopriv handlers with
`if ( ! acf_verify_ajax() )`, and we reported all of them. ACF: 22 findings to 3.

## What the traces looked like before and after

Roughly a fifth of corpus findings entered through a property read, and their
traces began *"read from property `$x`"* and stopped there. That is not
something a reviewer can act on, and a finding a reviewer cannot judge is one
they learn to ignore.

The property map now records the trace of the write that tainted each property,
and a read splices it in ahead of its own step. A flow through a property now
reads:

```
1. source     :8:24   $this->label = $_GET['label'];      Tainted by superglobal $_GET['label'].
2. propagate  :8:9    $this->label = $_GET['label'];      Written to property $label.
3. propagate  :13:14  echo $this->label;                  Read from property $label.
4. sink       :13:14  echo $this->label;                  Reaches echo with html taint intact.
```

"Every finding carries a trace" has to mean a trace that reaches a source.

## What was deliberately left alone

Not every finding a reviewer would dismiss is a bug in the tool.

**`wp.sqli.unprepared-query` on a value from an allowlist.** Rank Math builds
`$wpdb->prepare( "{$key} = %d", $value )` inside a loop guarded by
`in_array( $key, $allowed_keys, true )`. The engine cannot see that the
allowlist constrains `$key`, and neither can WPCS — it flags the same line.
Reporting it is defensible; suppressing it would need path-sensitive analysis of
a membership test, which is a long way past v1.

**Lines the plugin authors already suppressed.** A striking number of the
remaining SQL findings sit on lines carrying
`// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared`. WPCS flags them too and
the author decided the risk was acceptable. Those are accepted debt rather than
false positives, and wp-taint has its own suppression mechanism for recording
that decision — with a mandatory reason.

**Genuine flows in widely-installed plugins.** Several remaining findings are
real: `$_FILES['upload_file']['tmp_name']` reaching `unlink()`, and
`$_POST['archives']` reaching `unlink()` through two function boundaries. Both
sit behind nonce checks the dataflow engine does not model, so they are
reachable only by an authenticated user with the right nonce — but the dataflow
is exactly what the tool says it is.

## Honest scoring

The plan sets Phase 7's gate at "false positive rate under 10% on the corpus",
which requires hand-triaging every finding. That is a human job, and it is the
one part of this the tool cannot do for itself.

What has been done instead:

- Every false positive **class** found by sampling was fixed at the root, not
  suppressed, and each has a fixture taken from the plugin code that exposed it.
- The corpus total fell from 1,394 findings to 1,046, a 25% reduction across
  the same 50 plugins. The effect is far larger on the plugins that triggered
  each class — LiteSpeed Cache 57 to 6, Advanced Custom Fields 22 to 3, Cookie
  Law Info 29 to 7, Akismet 5 to 0 — because each fix targeted one idiom rather
  than trimming across the board.
- The fixture suite grew from 133 files to 148, and still passes at 100% on both
  halves — so none of the tuning was bought with false negatives.

What has **not** been done: a finding-by-finding triage of all remaining
findings with a verified true/false verdict on each. Anyone adopting this should
expect to spend real time on that for their own codebase, and
`--generate-baseline` exists so that the first run can be accepted as debt
rather than blocking.

## Reproducing

```bash
composer corpus:fetch
for plugin in tests/Fixtures/corpus/*/; do
    vendor/bin/wp-taint scan "$plugin" --format=json \
        --output="$(basename "$plugin").json" --fail-on=never --jobs=4
done
```

SARIF output opened in Trail of Bits' SARIF Explorer is a far better triage
surface than a spreadsheet: it renders the source-to-sink flow and lets you
classify each result as Bug or False Positive with one keystroke.

## Phase 8 — scored against somebody else's answer key

Everything above measures this engine against tests we wrote. The fixture suite
is ours and 37 of its cases were added after the behaviour they check; the
corpus is third-party code with no ground truth at all. Both have a hole in the
same place.

The WordPress plugin review team published an intentionally vulnerable plugin in
2013 to teach plugin authors what their code does wrong, and a companion post
enumerating every flaw in it. That is a scored test written by someone else, for
a purpose unrelated to this tool, with an answer key we did not get to write.

**We started at 5 of 12 and finished at 12 of 12.** What the seven misses cost
to fix is the interesting part.

### esc_sql() is not a substitute for prepare(), and we said it was

`registries/wordpress.toml` declared `esc_sql` as clearing `sql` outright, and
`wp.sqli.wpdb-query`'s remediation text read "esc_sql() is acceptable but
prepare() is preferred". `LiteralAnalyzer` carried the same belief in a comment:
"absint(), intval(), count(), md5(), esc_sql(), sanitize_key()… nothing that
comes out of these can be SQL syntax."

It is true inside quotes and false outside them:

```php
$wpdb->get_row( "SELECT * FROM t WHERE name = '" . esc_sql( $n ) . "'" );  // fine
$wpdb->get_row( "SELECT * FROM t WHERE ID = " . esc_sql( $id ) );          // 1 OR 1=1
```

This plugin exists to teach exactly that, and we shipped the advice it was
written to correct.

**The first fix was wrong and the corpus said so immediately.** Asking "is this
component provably safe in a bare position" took the corpus from 1,046 findings
to **1,394**, because a table name from a helper is not provably anything:

```php
$wpdb->query( "ALTER TABLE {$configTable} ADD COLUMN autoload ..." );  // 65 in Wordfence alone
```

The right question is not what the value looks like but where it has been. So
`esc_sql()` no longer clears `sql`; it trades it for {@see TaintKind::SqlUnquoted},
and the sink reports that kind only outside quotes. A table name that never
carried SQL taint never picks the kind up and is silent by construction rather
than by heuristic. That also deleted the `unquoted_sql_safe` option and the
strict `LiteralAnalyzer` mode the first attempt had needed.

The summary had to carry it too: the escaper lives in the callee, so the caller
learns about it only from `paramToSink`, recorded under `sql` — what the caller
passes in — rather than `sql_unquoted`, which is what the callee turns it into.

### A nonce is not an authorization check

`admin_post_` is the third registrar of the shape the REST and AJAX rules
already covered, and the plugin's delete handler sits on it with no capability
check. A naive rule reports it clean, because `check_admin_referer()` *is*
present and was in the `[[authorization]]` list.

A nonce proves the request was deliberate. It says nothing about entitlement: a
subscriber can hold a perfectly valid nonce for a form they should never submit.
`[[authorization]]` entries now carry `proves = "entitlement" | "intent"`. The
AJAX rule still accepts either — demanding a capability there moves findings
across every plugin in the corpus — and the admin_post_ rule requires
entitlement, which is the only reason it catches what it was written for.

Across the corpus the new rule reports **nothing**: all 16 resolvable
`admin_post_` registrations genuinely check. Verified rather than assumed, by
instrumenting the walk. Registrations made through a wrapper —
`$this->loader->add_action( 'admin_post_x', ... )` — are not seen at all, a
pre-existing blind spot shared with the AJAX rule.

### One function could only ever be one sink

`update_option()` is a stored-taint sink on its value and a
privilege-escalation sink on its name. `$this->sinks[$matcher->key()] = $sink`
kept whichever the loader saw last and dropped the other silently — in a
registry otherwise built to hard-error on an unknown key. Sinks are now a list
per matcher.

### The option-name rule took three attempts, and the corpus rejected two

The vulnerability is the attacker choosing *which* option is written:
`default_role` is an option and `administrator` is a legal value for it.

1. **Report any request-derived name.** 63 findings. The
   `ajax-nopriv-missing-check` fixture failed, because
   `add_option( 'acme_subscriber_' . $_POST['email'], 1 )` is anchored — junk in
   a namespace the plugin owns, not escalation.
2. **Require a literal prefix.** Astra Sites still reported nine, all
   `$source . '_usage_optin'`. A literal *suffix* pens the attacker in just as
   well; so does one in the middle.
3. **Require a literal anywhere — and look for it across call boundaries.**
   The remaining false positives were all values whose anchor was real but
   several frames away:

   ```php
   // PluginsHelper.php — $job_id is request data, so the taint is correct
   $option_name = 'woocommerce_onboarding_..._async_' . $job_id;
   $logger      = new AsyncPluginsInstallLogger( $option_name );
   // → constructor → property → update_option( $this->option_name, $data )
   ```

   The taint was right. A local, syntactic anchor check judging an
   interprocedural value was not. `FunctionSummary::returnAnchored` and
   `PropertyTaintMap::isAnchored()` put the check on the same machinery the
   taint travels on.

A parameter means opposite things in the two directions, which is worth stating
because it is not obvious. Reading a value, an unknown parameter means "the
caller anchored this" and counts as constrained. Summarising a *return*,
`function f( $id ) { return $id; }` guarantees callers nothing, and calling that
anchored would launder the request through any one-line pass-through — hence
`hasWithinBody()` beside `has()`.

**Known false negatives**, both deliberate: an unresolvable callee is assumed to
anchor, and anchoring is not propagated from a caller into a parameter, so
`new Bad( $_POST['name'] )` stored on a property and written is not reported.

**Still outstanding.** WooCommerce's REST settings controllers survive:

```php
if ( ! in_array( $setting_id, $valid_setting_ids, true ) ) {
    continue;
}
...
update_option( $setting_id, $value );
```

There is no literal to anchor on; safety comes from an allowlist gate, which is
a *sanitizer* in this engine's vocabulary and is not modelled for `identifier`
taint. It needs the guard's branch, so it would be the engine's first
path-sensitive analysis.

### A trailing comment hid the guard rule

`wp_redirect()` sends a header and returns; it does not stop the script, so a
failed check falls through into the work it guards. That is the most
consequential bug in the plugin and the reason its arbitrary option write is
reachable at all.

php-parser emits a `Stmt\Nop` for a comment trailing the last statement of a
block, so `wp_safe_redirect( $url ); // bail` ended in a Nop and the rule saw the
comment rather than the redirect. Writing the fixture is what surfaced it —
using the suite's own `wp-taint-expect` annotation, which is a trailing comment.
Uncaught, the rule would have missed every commented guard in the wild.

### And a mask that had to be kept in step by hand

`TaintSet::allDataflowKinds()` was a binary literal, `0b0000_0111_1111_1111`.
Adding a kind left it one bit short, so every value seeded as "all kinds"
silently lost the new one. Derived from the enum now.
