# Tuning against the corpus

What running the WordPress.org top fifty actually taught, and what changed as a
result. This is the record of Phase 7.

The corpus is 50 plugins, 24,792 PHP files, 3.7 million lines. It is not
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
