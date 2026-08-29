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

## Phase 9 — measured against real CVEs, and what that found

Phase 8 scored 12 of 12 on a plugin written for teaching. 47 published CVEs in
real plugins scored **8 attributed, 17 unattributable, 22 silent**, and the gap
between those two results is the useful part: textbook bugs written to be found
are not the same as bugs that got past a maintainer.

Three classes scored zero, and the reasons differed.

### Object injection: a real gap, and the reasoning that caused it

Stored sources carried `html`, `html_attr` and `sql` and nothing else, with a
note explaining why: an attacker who can write an option already has the access
the `path` and `url` sinks would give them.

That reasoning is correct and does not extend to `unserialize`. Object injection
grants *more* than the write did: a subscriber-level meta write becomes RCE
through a POP chain in whatever classes happen to be loaded. It is the classic
WordPress escalation, and three of the pinned CVEs are exactly it.

Adding the kind caught CVE-2023-1196 in Advanced Custom Fields — five findings
before the fix, none after — and cost 79 corpus findings, all in the new class.

**Then it had to be calibrated.** 91 findings at `critical`, next to the 12 that
need no precondition at all, devalues the word for both. WordPress reads its own
serialised meta constantly. So stored object injection has its own kind and its
own rule at `high`, and `wp.rce.unserialize` keeps `critical` for a request
reaching `unserialize()` directly.

`unserialize( $data, [ 'allowed_classes' => false ] )` is not reported. It is
the documented fix — what Better Search Replace shipped for CVE-2023-6933 — and
flagging code that already applies it tells people to do what they have done.
Two attempts were needed: `false` arrives as a temporary defined by a
`ConstFetch`, not as a boolean literal, so the obvious test silently answered no
for the only spelling that appears in source.

Two CWE-502 cases remain silent, both deep chains: a recursive function calling
a static method through `$this` on an element of a `get_results()` row.

### Open redirect and code injection: mostly the label, not the rule

All three CWE-601 cases turned out not to be `wp_redirect()` flows. Contact Form
7's is a request URI reaching a form `action` attribute, which manifests as
attribute injection; WPS Hide Login's fix adds a conditional early return inside
a `wp_redirect` filter callback, which is a logic bug with no dataflow to see.

The five CWE-94 cases are Code Snippets, Insert Headers and Footers, WP Super
Cache and Loco Translate — plugins whose purpose is executing admin-supplied
code. Those CVEs are privilege-boundary bugs wearing a code-injection label.

Genuine gap found anyway: `header( 'Location: ' . $url )` is reported as header
injection rather than as an open redirect, because only `wp_redirect()` carries
the redirect rule.

## Phase 9b — hooks nobody was registering

Eight of the fifty corpus plugins register hooks through their own loader rather
than calling `add_action()` where a scanner can see it. Those registrations were
not unresolved. They did not exist: nothing identified them as registrations, so
they were never counted, never reported, never walked.

A clean authorization report on a boilerplate-generated plugin meant the rules
had not run.

Three arg layouts cover what the corpus contains — the WPPB
`$loader->add_action( $hook, $component, 'method' )`, a wrapped array callback,
and a bare method name on `$this`. A method named `add_action` counts whatever
its receiver, because every plugin names its loader differently and the name is
the only stable signal.

The fix applies to the hook *graph* as well as the authorization rules, so taint
now crosses a wrapped filter. That was the larger half: a registration the graph
cannot see is a callback that never receives taint and a dispatch that never
returns it.

The component's class comes from the one `new` naming that variable in the same
file, which is what the boilerplate always does. Two different classes assigned
to the same name means the answer depends on control flow, and crediting the
wrong method body for an authorization check is the failure this rule exists to
prevent, so it gives up instead.

Corpus: 1,073 to 1,163.

## Phase 10 — escaping has to survive to the sink

A plain taint model reports nothing at all on this:

```php
$title = esc_html( $_GET['title'] );
echo apply_filters( 'acme_title', $title );
```

The escaper clears the taint and nothing puts it back. Any plugin on the site
may hook `acme_title` and return whatever it likes, and this code prints it.
That is why the practice is called *late* escaping: it has to be the last thing
that happens to a value, because everything afterwards is another chance to
undo it.

An escaper marks its result; a call that hands the value to somebody else trades
that mark for `escape_voided`; the output construct reports it under its own
rule at medium, one band below never having escaped at all, because it needs a
second plugin to actually hook the filter.

### Which calls void it is generated, not guessed

The obvious version — void on `apply_filters()` — misses the commonest case by
far, which is an ordinary-looking core function with a filter inside it:

```php
echo wp_trim_words( $escaped, 20 );   // 'wp_trim_words' runs inside
```

Guessing by name (`wp_`, `get_`) would be a heuristic. This is a fact about a
WordPress checkout, so `tools/generate-filterable-catalogue.php` derives it:
4,272 core functions read, 933 mention a filter, **569 return one**.

Three corrections, each found by measuring rather than reasoning.

**Pattern-matching two spellings was too narrow.** `return apply_filters(...)`
and `$x = apply_filters(...); return $x;` miss the case where the filter and the
return are several statements apart, which is most of how core is written. A
fixed point over the body — a variable is filtered if assigned from a filter or
from anything mentioning an already-filtered variable — took it 524 to 629.

**Passing a value as an argument does not make the result derive from it.**
`$rval = $wpdb->update( $table, $data )` returns a row count, not `$data`. Calls
are opaque now, except a named list of string builders, because
`_navigation_markup()` genuinely ends `return sprintf( $template, ... )` with a
filtered `$template` and a plugin hooking it controls the markup. 629 to 569.

**Which parameter matters.** `wp_update_comment( $comment )` takes a value in
and returns a row count; `get_the_title( $id )` filters a title it fetched
itself. Voiding on "any escaped argument" reported both, so the catalogue
records the parameter positions the filtered return actually comes from.

### Two exceptions that had to be written down

**Every WordPress escaper is itself filterable.** Core ends `esc_html()` with
`return apply_filters( 'esc_html', $safe_text, $text )`, so the generated list
contains it, and taking that literally makes every escaper void its own work. A
site with a hostile `esc_html` filter has a problem this rule cannot usefully
report at ten thousand call sites.

**Numeric coercion is not escaping.** `absint()` clears every kind, and marking
its result escaped made `echo get_the_title( absint( $_GET['id'] ) )` look like
voided escaping — the *id* carried the marker into a call whose result has
nothing to do with it.

**And escaping after the filter clears the voiding**, because that is the
correct order. Cookie Law Info does
`wp_kses_post( apply_filters( 'x', esc_html( $v ) ) )`, which is safe however
the filter behaves, and the rule reported it until this was fixed.

### What it found

Corpus 1,163 to 1,399; the rule accounts for 236. Sampled, they hold up. Akismet
does `echo apply_filters( 'akismet_..._markup', '<p>' . wp_kses( ... ) )`, and
WooCommerce does this with a comment that says it out loud:

```php
// KSES is ran within get_description, but not here since there may be custom
// HTML returned by extensions.
echo wpautop( wptexturize( $description ) );
```

One known false positive, on the plugin pinned to zero to catch exactly this
kind of thing. `wp_update_comment()` is listed as returning its first parameter
filtered because core contains `if ( false === $data ) { return $data; }` after
the filter — a return only reachable when the value is `false`. The generator is
right about the syntax and wrong about the semantics, and knowing the difference
needs path-sensitivity a generated list cannot have.

## Phase 11 — two suites nobody here wrote

Every benchmark up to now had the same hole in a different place. The fixture
suite is ours, and 47 of its cases were written after the behaviour they test.
The corpus is third-party code with no answer key. The CVE set has an answer key
and no line-level ground truth, tests 14% of what was available, and its nine
"attributed" cases split four strong to five that could be code churn.

Two labelled suites arrived with their own scorers. They cover *semantics* —
context correctness, escape invalidation, weak sanitisers posing as real ones —
where the corpus covers volume and the CVE set covers incidents.

The first run was the useful one:

    precision 0.93   recall 0.59   F1 0.72

Precision was the good news and stayed good news through everything below.
Recall had three causes, and two were whole missing rules.

### An escaper can be present and still be wrong

Zero of five. `esc_html()` inside `<script>`, `esc_attr()` on an `href`, any
escaper in an unquoted attribute — every one has a visible `esc_*` call and
every one is exploitable. "Was an escaper applied" and "was it the right one"
are different questions and the engine only asked the first.

Structural rather than dataflow, because the context belongs to the literal text
around the hole rather than to the value. The attribute scanner reads forward
rather than matching the tail: `onclick='doThing("` is still inside `onclick`,
and a regex anchored at the end of the string loses precisely the case the rule
most wants.

Two corrections, both from our own fixtures rather than theirs. `wp_get_referer()`
is a *source*; reporting it as the wrong escaper misnames the problem and
duplicates the ordinary output rule. And `sanitize_html_class()` is a legitimate
attribute escaper. Only recognised escapers are judged now — a function this
rule has no opinion about is left alone.

### The third answer for provenance

Nine of the suite's cases are this:

```php
function fx_render_bad( $value ) {   // "assumed tainted (option, meta, query var)"
    echo $value;                     // ruleid: wp.output.unescaped
}
```

A parameter with no caller. The engine had two answers — tainted or clean — and
gave the second to anything it could not trace, which scored the output half at
**0.18 recall**.

That default is a reasonable answer to "can I prove this value is dangerous" and
the wrong answer to "is this value proven safe". WordPress's own standard asks
the second: sanitise on input, escape on output, each owed wherever the value
came from. `TaintKind::Unknown` is the third state, seeded on parameters and
cleared by any sanitizer, because applying one settles the question either way.

Behind `--unknown-provenance` and off by default, because it changes which
question the tool is answering rather than making it better at the old one.

    output.unescaped     0.18 -> 0.82
    output.wrong-context 0.00 -> 1.00
    overall recall       0.59 -> 0.84
    overall F1           0.72 -> 0.89
    precision            0.93, unmoved throughout

### What it cost

Corpus 1,399 to roughly 1,500 with the flag off, and 2,566 with it on — 926 of
those the obligation rule. Far below the 14,000 a crude estimate had suggested,
because it fires on parameters rather than on every `echo`, and any sanitizer
clears it.

One pinned plugin moved a long way: WP Super Cache 9 to 41, all of it
`esc_url_raw()` in form `action` attributes. Our own catalogue already says
esc_url_raw is for storage and redirects rather than output, and WPCS rejects it
for output too, so the findings are right and the plugin has one habit repeated
32 times.

### Still not solved

Path sensitivity. `if ( ! in_array( $mode, $allowed, true ) ) { $mode = "grid"; }`
and `if ( ! ctype_digit( $id ) ) { return; }` both leave a value the engine
cannot see is constrained, and they are the last three false positives in the
suite as well as the cause of the WooCommerce and Duplicator false positives
found by corpus triage.

It is not a rule that is missing. The engine keeps one `TaintState` per function
rather than per block, which is why it converges cheaply and why a branch
condition has nowhere to be recorded. Fixing it means per-block state, and this
project has had five separate convergence failures in exactly that machinery.
Worth doing, and not worth doing carelessly.

## Phase 12 — path sensitivity, which was never the blocker it looked like

Three false positive classes had the same diagnosis: a guard the engine could
not see. WooCommerce validating an option name with `in_array`, Duplicator's
vendored copy of core's `wp_specialchars()`, and two cases in a third-party
suite labelled safe.

The diagnosis before this phase was that fixing it needed per-block state, and
that the engine's single `TaintState` per function — the thing that makes its
fixed point cheap — stood in the way. Five convergence failures have come out of
that machinery, so it was left alone.

**That was wrong, and dumping one CFG showed it:**

```
Block#2 (guard taken)              Block#3 (fall-through)
  Expr_Assertion<not(type(int))>     Expr_Assertion<not(not(type(int))>
    expr:   Var#3<$id>                 expr:   Var#3<$id>
    result: Var#7<$id>                 result: Var#8<$id>
```

php-cfg gives each branch its own operand. The paths were always separable; the
engine was passing taint straight through the assertion that said so. A comment
in the transfer explained why — `isset()` and `empty()` produce an assertion
whose result is an operand *already written* by the op that produced the value,
and narrowing there gives one operand two writers. True, and true only of that
shape. Narrowing when the operands differ has one writer and cannot oscillate.

### The checks php-cfg does not assert on

`ctype_digit`, `in_array`, `preg_match` produce no assertion, so those needed
their own answer. The first attempt walked `Block::parents` and stopped at any
join, assuming a guard clause leaves a linear chain. It never fired once: the
fall-through block of a guard has two predecessors in php-cfg's output.

Dominance is the question that was actually being asked — is the validating edge
on *every* path to this sink — and it is a standard fixed point over the block
graph. Computed once per function, consulted at reporting time, and able only to
suppress a finding, so no part of propagation changes.

### The polarity that was backwards

`ctype_digit()` proves safety when it succeeds. `preg_match( '/[&<>"\']/' )`
proves it when it *fails*. The first implementation asked "did the predicate
hold" and treated that as "is the value safe", which is right for one and
inverted for the other.

That second form is not an edge case. It is core's own fast path:

```php
if ( ! preg_match( '/[&<>"\']/', $string ) ) {
    return $string;
}
```

Every plugin that vendors a copy of `wp_specialchars()` inherited a false
positive from us. It also needed the *return* narrowed rather than a sink
suppressed, because the value leaves that way.

### What it bought

    third-party suite   precision 0.93 -> 0.98, false positives 3 -> 1
    Duplicator          103 -> 91 findings
    corpus              1,622 -> 1,610

### What it did not buy

WooCommerce's controller still reports. The guard is in one loop and the sink in
another, over an array populated under the guard, and the guard genuinely does
not dominate the sink. Proving that safe is container reasoning — every write
into this array happened under a guard — and is a different piece of work.


## Triage pass: 1,610 findings to 1,078

A sampling triage across every rule, largest first, fixing what it turned up.
Nine changes; the benchmarks held through all of them.

    corpus            1,610 -> 1,078 findings   (-33%)
    critical            352 -> 102              (-71%)
    vulnerable plugin  12 of 12, unchanged
    wp-taint-fixtures  TP=46 FN=18 FP=0 TN=44, unchanged
    analyser-fixtures  missing=10 unexpected=7, unchanged

### A probe's seed was being recorded as a fact

The largest single cause, and the least visible. Summaries are extracted by
running a body once per parameter, seeding that parameter with every taint kind.
Those runs shared the scan's property map, so the seed was written into it:

```php
function __construct( $file, $level ) {
    $this->file = $file;              // probed with every kind
}
```

left `MC4WP_Debug_Log::$file` permanently holding html, sql, path, shell, eval
and ten more. `explain` said so in as many words. 334 findings rested on a seed
like that one — Twig's template compiler as an eval sink, phpseclib's Barrett
reduction twice, monolog's configured `proc_open()`, Wordfence's own view loader
as local file inclusion after it had run the path through `preg_replace`.

Probe runs now get a sealed copy: reads work, writes go nowhere. The copy is
shallow and never writes an array, so PHP never copies one.

That lost the flow the over-approximation had been catching by accident, so the
second half adds `paramToProperty` — the write counterpart to `paramToSink`. A
probe records which properties its parameter reached; the call site applies the
taint the caller actually passed. The trace improved, because it now has
somewhere real to start:

    1. source     $log = new Acme_Logger( $_GET['f'] );
    2. propagate  Passed to Acme_Logger::__construct(), which writes it into $file.
    3. propagate  file_put_contents( $this->file, $line, FILE_APPEND );

### Escaping a literal, twice over

`wp.xss.escape-voided` went 358 -> 162 through two fixes with the same shape.

Intraprocedurally: `esc_html__( 'The root URL of your site.', 'woocommerce' )`
is a fixed English sentence before the call and the same sentence after it. The
marker is now withheld when every argument the escaper reads is a compile-time
constant. Testing "carries no taint" instead cost four true positives — a
function parameter carries no taint either, and that is the case the rule exists
for.

Interprocedurally: `wc_help_tip()` genuinely ends `return apply_filters(
'wc_help_tip', … esc_attr( $aria_label ) … )`, which a summary records as
introduced. All 65 call sites in WooCommerce's system status report inherited
it, each passing a fixed English sentence. The markers are a claim about a
value; with no tainted argument they have no value to be about.

### Severity that follows the evidence

187 of the corpus's 352 criticals were `wp.sqli.prepare-non-literal` on this:

```php
$wpdb->prepare( "UPDATE `{$table}` SET `vtime` = LEAST(`vtime`, %d)", $t );
```

The rule's own description says taint analysis could not prove the value is
attacker-controlled. The query-shape rule next to it already settled the
convention — high without a proven path, critical with one — and this rule now
follows it.

### Three claims that were not true

**`esc_url_raw()` in a double-quoted attribute.** Both variants run the same
filter; the whole difference is the display-context block that encodes the
apostrophe. The character filter strips `"`, `<`, `>` and space in both, and the
scheme allowlist rejects `javascript:` in both. So the quote character decides
it, and WP Super Cache's 32 `action="…"` forms were all being called wrong.

**`wp.header.injection` carried CWE-113** and told 28 findings to strip CR and
LF. PHP rejects both inside `header()` and refuses to send the header; sending
`setcookie()` a value urlencodes it first. What is left needs no newline —
a Content-Type that decides whether the body is HTML, a Location that decides
where the visitor goes, a cookie name that shadows the session cookie — and that
is what the rule says now.

**`$_FILES['f']['tmp_name']`** is PHP's own path under `upload_tmp_dir`, and
reading it is the only way to read an upload. Ten plugins were told it was path
traversal. `sub_keys` on a source names which second-level keys are the
client's: `name`, `type`, `full_path`.

### Advice that broke the endpoint

18 of 49 `wp.authz.ajax-missing-check` findings are on `wp_ajax_nopriv_*` hooks,
and every one was told to add `current_user_can()`. That cannot pass for a
logged-out visitor, and the handler is on that hook so logged-out visitors can
reach it. The finding stands; what it asks for is now a nonce, or a deliberate
decision that the endpoint is public.

### Storage and output are different obligations

`update_option( 'endpoint', esc_url_raw( wp_unslash( $_POST['endpoint'] ) ) )`
is exactly right for storing a URL and exactly wrong for printing one. The write
side was borrowing the `html` kind, which made them indistinguishable.
`TaintKind::Storage` is the input obligation: carried by every request-facing
source, cleared by any sanitizer and by no propagator, which is what keeps
`trim()` and `wp_unslash()` from passing for sanitisers. It took the third-party
suite to precision 1.00.


## Narrowing --unknown-provenance to entry points

The flag marks a parameter as unvouched-for and reports it if it reaches output
unescaped. It was marking every parameter, including ones the scan can answer
for itself:

```php
function acme_render( $title ) { echo $title; }
acme_render( esc_html( $x ) );          // right there
```

The caller settles that. Reporting it anyway is the tool saying it does not know
something it has already read.

The real case is a function nothing in the scan calls: a callback on a hook core
dispatches, a public API a theme uses, a template WordPress includes. The call
graph already answers that — it is built before analysis and the authorization
rules already walk it — so the only new part is a reverse index and one question
at the seeding site. The hook graph is folded into those edges, which makes the
distinction right for free: a callback whose `apply_filters()` dispatch is in the
scan has a caller and its arguments are read from that dispatch; one registered
on `init` has none.

    corpus, flag on     +926 -> +142 findings
    wp-taint-fixtures   recall 0.72 -> 0.84, F1 0.84 -> 0.91, precision 0.98

Same recall as before the narrowing. The 784 that went away were never buying
it — about three findings per plugin now rather than eighteen, all at `low`,
below the default `--fail-on=high`.

Still off by default. It asks a different question — "is this proven safe"
rather than "can I trace this to something dangerous" — and which one you want
is a decision about the review.

## Following a receiver through a plugin's singleton

`DeclaredTypes` is a project-wide index of what the code says about itself:
declared return types, typed properties, promoted constructor properties, and
`$this->x = new Foo()` anywhere in a class. It exists for the shape every
substantial plugin is built on:

```php
$table_name = code_snippets()->db->get_table_name();
$wpdb->get_results( "SELECT * FROM $table_name" );
```

Before it, `$db` fell through to the convention that reads a receiver of that
name as the database handle, resolving the call to `wpdb::get_table_name()`,
which nothing defines. That convention is now a fallback rather than an
override, which was its own fix: a declared `Acme_Store $db` had been losing to
it.

It bought three findings. That is not the number this was aimed at, and the
reason is recorded below.

## Where the SQL shape findings actually come from

Two changes aimed at `wp.sqli.prepare-non-literal` moved it by three, so the
shape rule was instrumented to record what it fails to account for, per reported
finding rather than per evaluation — the two give very different answers, and
the per-evaluation one is what produced the wrong estimate.

    46  Assign          a chain; bottoms out in one of the others
    33  Phi             merged from branches, one of which failed
    27  PropertyFetch   a table name on $this
    25  ConcatList
    22  Param           a table name arriving as an argument
     6  ArrayDimFetch
    13  calls and no-writer

Three distinct causes, none of them cheap:

**A table name passed as an argument** is 22 of 174 — about 13%. Resolving it
means an interprocedural fixed point over "does every caller pass a resolved
value", which is the shape of problem that has caused five separate
non-convergences in this project. Wrong trade.

**A table name behind a service locator.** LiteSpeed is representative:

```php
$this->__data = $this->cls( 'Data' );
$this->_table_img_optming = $this->__data->tb( 'img_optming' );
```

`cls('Data')` picks a class by string argument. No declared type resolves that;
it needs constant-argument-sensitive return typing.

**A class outside the scan.** Jetpack calls WooCommerce's
`OrdersTableDataStore::get_orders_table_name()`. Scanning Jetpack alone, that is
genuinely unknowable, and the `[scan] reference` config is the answer rather
than a code change.

So the rule is left as it is. It is honestly labelled — its own description says
taint analysis could not account for the value — and since the severity change
it is ranked `high` rather than `critical`, which was the part that actually
misled.


## Fixing the misses an answer key names

Rather than picking from the limitations list, this started from the 18 labelled
cases `wp-taint-fixtures` says are missed. Each one is a specific claim that can
be read, diagnosed and either fixed or refused.

    default             P 1.00  R 0.72 -> 0.77   F1 0.84 -> 0.87
    --unknown-provenance  P 0.98  R 0.84 -> 0.94   F1 0.91 -> 0.96
                                 FN 10 -> 4

### printf() had one sink where echo has three

`echo` and `print` each carry `html`, `unknown` and `escape_voided`. `printf()`,
`vprintf()` and `var_dump()` had only the first: the other two were added
alongside `echo` and the rest of the family was missed. Nothing about `printf()`
makes it different — it writes the same bytes to the same place.

### Closures captured nothing

    $raw = $_GET['msg'] ?? '';
    add_action( 'wp_footer', function () use ( $raw ) { echo $raw; } );

The body is a separate function and the captured variable arrives inside it as a
free operand, so nothing connected the two. A capture is the same shape as an
include's scope — a map of names to taint crossing a boundary — so it uses the
same table.

Two things had to be right. **By name, not by operand:** php-cfg gives the `use`
clause its own fresh `Variable` nodes rather than the SSA temporaries holding
the values, so asking those operands what they carry answers "nothing" every
time. And **a probe run must not publish**, which is the mistake the property map
made, with the same fix.

### A shortcode is an entry point at both ends

WordPress hands the callback attributes from the post body and prints what it
returns. Three things had to be true: the registration had to be seen
(`add_shortcode()` shares `add_action()`'s argument layout, so the hook graph
already knew how), the parameters had to carry post content, and the return had
to count as output — there is no `echo` to find, because `do_shortcode()` does
the printing.

Underneath was a catalogue gap: `shortcode_atts()` was listed as filterable and
never as a propagator, so its return read as clean and every callback that
normalises its attributes the usual way lost the taint on its first line.

### register_setting() without a sanitize_callback

Core reads `$_POST` and core writes the option; the plugin's only involvement is
the registration. There is no flow to follow, which is why it is a structural
rule. Yoast's Duplicate Post registers every one of its options in a loop with
no callback on any of them.

### One refused

A REST callback's return is not treated as output. It is JSON-encoded and served
as `application/json`, so a browser does not render it as markup, and reporting
every callback that returns a string built from a request parameter would be
noisy and mostly wrong. The fixture assumes a downstream HTML consumer that is
not visible from the callback. Sinks *inside* the callback report normally.


## Unknown provenance on by default

Measured before flipping it, because "does it cost anything" is the question
that decides it.

    KFF, 926 files    off 47.2s / 52.4s    on 48.9s / 46.9s

No measurable overhead. Seeding a marker on an entry point's parameters is not
extra work for the fixed point; the same passes run either way. What it costs is
findings, all at `low`, which is below the default `--fail-on` and so cannot
fail a build on its own.

    wp-taint-fixtures   P 1.00 R 0.77 F1 0.87  ->  P 0.98 R 0.94 F1 0.96
    corpus              1,078 -> 1,326 findings, the 157 new ones all `low`
    KFF                 22 -> 30 findings, the 8 new ones all `low`

The argument for it is that a reader who knows a value is safe dismisses a `low`
in a second, and a reader who is never shown it cannot. The argument against was
that the eight it adds on a real client theme are one pattern — Gutenberg inner
blocks, which are meant to be echoed raw — and that is a weak reason to withhold
the other eleven true positives it finds on labelled code.

The fixture harness now runs with defaults rather than pinning the flag off, so
the regression net tests what ships. All 118 labelled-safe fixtures stay clean
with it on, which is the number that mattered.

`--no-unknown-provenance` asks the narrower question.

### Functions that prepare their own output

VIP's guidance that "some WordPress functions properly prepare the data for
output" was the obvious thing to break, and it does not, without a list of those
functions existing anywhere in the catalogue.

    echo wp_get_attachment_image( $id, 'large' );        // silent
    echo get_avatar( $id );                              // silent
    echo wp_nav_menu( $args );                           // silent
    echo paginate_links( $args );                        // silent

Two separate things keep it that way. `wp.output.unescaped-unknown` needs the
marker to reach the output, and none of these is a propagator, so nothing
carries through them — an unmodelled return is clean, which is usually the
under-approximation this project apologises for and is exactly right here.
`wp.xss.escape-voided` needs evidence that something *was* escaped before the
filterable call, and echoing one of these provides none.

The pairing at the escape-voided sink is what does that work, and it was put
there for a different reason: without it `echo get_option( 'x' )` reported twice,
once as unescaped output and once as voided escaping. It turns out to be the
same requirement.

The one shape that does report is escaping something on the way *in*:

    echo wp_get_attachment_image( $id, 'large', false,
        array( 'alt' => esc_attr( $title ) ) );

Redundant rather than wrong — core escapes those attributes itself — and the
advice attached to it is imperfect, since the `<img>` markup that comes back
cannot be escaped afterwards. Rare enough to leave.


## Reading the second suite's misses

`ideas/wp-taint-analyser-fixtures` had reported `missing=10` on every run all
along and had never been read finding by finding. Doing that split them three
ways.

**Three were not misses.** F14, F15 and O09 are found — reported as
`wp.xss.unescaped-output` and `wp.xss.wrong-context-escape` where the suite's
vocabulary expects `output.escape_invalidated` and `output.wrong_context_escape`.
That is the adapter being deliberately conservative about which of our rule ids
may claim which of theirs, not the engine failing to find the bug.

**Two were missing catalogue entries.**

    $body = wp_remote_retrieve_body( wp_remote_get( $endpoint ) );
    echo $body;                                          // F17
    update_option( 'cache', $body );                     // I08

The endpoint may be one the plugin chose; the bytes that came back are not. It
carries the stored kinds for the same reason `get_post_meta()` does, and no
`path` or `url` for the same reason either.

    wp_add_inline_script( 'app', "window.m = '" . $message . "';" );   // F18

Prints into a `<script>` block, so a single quote closes the string literal and
the rest is code. No HTML escaper protects it.

**One was a real gap, and the largest of them.**

    register_block_type( 'acme/card', array( 'render_callback' => 'acme_render' ) );

`render_callback` appears in 110 files across the fifty-plugin corpus and 205
across two real client projects. WordPress calls it and prints what it returns,
so there is no `echo` in the plugin for a rule to find — the shortcode problem
exactly, so it reuses that machinery. Only the lookup is new: the callback
arrives under an array key rather than in a positional argument.

Its parameters are deliberately not seeded, unlike a shortcode's. A block's
inner content is already-rendered markup meant to be printed as it is, and a
real client theme echoes that value four times over.

### What is left

    F03, I06   a shortcode handler with no add_shortcode() anywhere. Both rules
               need the registration; convention is not a signal this reads.
    F16        a closure capturing by reference across two hooks. use ( &$x )
               writes back out to the enclosing scope and that is not modelled.

F16 is the only one of the ten that is a gap rather than a decision, and it is
the write direction of a boundary already crossed one way — the same shape as
the paramToProperty work.

    analyser-fixtures   missing 10 -> 7
    corpus              1,326 -> 1,323

### And then F16

`use ( &$x )` is a two-way binding and only one way was modelled. php-cfg keeps
the flag — each `use` is an `Operand\BoundVariable` with `byRef` on it — so
telling the two apart cost nothing.

A closure that writes to a by-reference capture now publishes what it assigned,
through the same table its captures arrive on. The enclosing scope reads that
back, and any other closure capturing the same variable receives it on the round
after. It only ever adds, so the fixed point stays monotone, and the write-back
is seeded once before the propagation loop rather than during it.

By-value captures are untouched: `use ( $x )` copies, and a write inside the
closure is invisible outside it. Both fixtures exist, because the difference
between the two spellings is the whole point.

    analyser-fixtures   missing 7 -> 6
    corpus              unchanged
    kff-shared          32.4s -> 32.4s

That leaves five, and every one of them is a decision rather than a gap: two
shortcode handlers with no `add_shortcode()` anywhere, `sanitize_text_field()`
credited at output, a REST callback's return, and a cross-component flow already
reported at the sink end.


## Four small misses, closed in one pass

Each had a one-line diagnosis in the misses table, and each fix landed where the
diagnosis said it would.

**A computed method name that folds to one string resolves.** `$m = 'verify';
$this->$m();` was unresolvable, which walked an AJAX handler's capability check
straight past the authorization rule — a checked handler reported as unchecked.
The value resolver already answered this question for hook names and class
names; the method-call path just never asked it. Several possible strings stay
dynamic, because picking one would be a guess.

**A loader component on a property resolves.** `$this->loader->add_action(
$hook, $this->admin, 'handle' )` could not name `$this->admin`'s class, so the
callback had no body and a missing check was invisible. The class is in the same
file three ways — a typed declaration, a promoted constructor parameter, or a
single `$this->admin = new Acme_Admin()` — and the resolver now reads all three,
giving up on ambiguity for the same reason the variable path does.

**A pass-through named as a sanitize_callback is reported.**
`'sanitize_callback' => 'wp_unslash'` is the same as naming none, and the
catalogue already says so: it is a propagator, not a sanitizer. A user callback
that reaches no catalogue sanitiser stays accepted, because absence proves
nothing there — an allowlist check reaches no sanitiser and is exactly right.

**`wp_text_diff()` joins the filterable list.** The one content-returning
pluggable whose core definition does not run a filter, so the generated
catalogue could not see it. The rest of pluggable.php returns booleans, objects
and voids — nothing escaping could have been applied to.

    corpus, both suites and the vulnerable plugin unchanged
    four fixtures, one per fix


## Includes that would not fold, measured then fixed

The misses table called this a medium project aimed at `get_template_part()`.
Measuring first changed the target: across five big corpus plugins, 424
unresolved includes split into 272 pointing at WordPress core (out of scan by
design), ~100 crude-classifier noise, 38 genuinely dynamic — and the real
mechanical gaps were elsewhere.

**Theme constant chains** were the loudest failure on real client themes, not
plugins. `get_template_directory()` is a runtime question with a static answer
whenever the calling file is itself inside a theme in the scan:

    define( 'ACME_THEME_PATH', get_template_directory() . '/' );
    define( 'ACME_THEME_INC', ACME_THEME_PATH . 'includes/' );
    require_once ACME_THEME_INC . 'core.php';

One fold connects the chain. ThemeRoots reads the `themes/<name>/` convention
from the scanned file list — never the filesystem — and a client theme went from
17 unresolved includes to 9, the recovered nine being its entire `includes/`
tree. A plugin calling it resolves only when the scan holds exactly one theme.

**Templated returns.** `include self::get_view_filename( 'html-main.php' )`
where the helper returns `__DIR__ . "/views/$view"`. The constant-return table
now records a *template* — literal fragments around the function's own
parameters — when every return produces the same one, and a call with literal
arguments folds it exactly. A transformed parameter refuses: substituting into
`basename( $view )` would fold to a path the code never builds. The nested
interpolation mattered: `"/views/$view"` is its own op feeding the outer concat,
so extraction flattens recursively.

Honest yield on the corpus: eight includes, not the 159 the first crude
classifier suggested. The same fold serves hook names and every other string
question, and it found one non-obvious bug on the way: `fromConstantReturn`
never carried a recursion depth, so two templated helpers calling each other
looped until memory ran out.

**A bootstrap file**, suggested mid-implementation and nearly free: `bootstrap =
["wp-taint-bootstrap.php"]` in the config or `--bootstrap` on the command line,
for constants defined outside anything scanned — `ABSPATH` above all. It is
mechanically `reference` under a name that answers "where do I put the define".
Verified end to end: a bootstrap defining ABSPATH plus core referenced resolves
`require_once ABSPATH . 'wp-admin/…'` and carries a flow through it.

    corpus, both suites, vulnerable plugin   unchanged
    kff-org-modern includes                  17 unresolved -> 9
    585 tests
