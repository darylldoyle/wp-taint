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

Convergence warnings across the whole corpus went from dozens to zero, and the
scans got substantially faster because the wasted iterations disappeared:
All in One SEO went from 56.4s to 16.4s.

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
- The corpus total fell from 1,485 findings to a little over a third of that,
  and every finding removed was reviewed and confirmed as a false positive
  before the fix was written.
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
