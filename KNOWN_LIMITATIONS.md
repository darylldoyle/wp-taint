# Known limitations

Every static analyser is a pile of approximations. This file says which ones
wp-taint makes, so that a clean scan can be read for what it actually means
rather than for what you would like it to mean.

The design rule behind most of these: **prefer a documented false negative to an
undocumented false positive.** A tool that cries wolf gets muted and then
deleted, at which point its true positives stop mattering too.

Findings that crossed one of these carry `imprecise: true` in JSON output,
`properties.imprecise` in SARIF, and a note in the console. You can filter on it.

---

## Dataflow

### Array element taint is per-array, not per-key

```php
$context = [];
$context['title'] = $_GET['title'];   // taints the whole $context
$context['id']    = 42;

echo $context['id'];                  // reported, and it should not be
```

php-cfg lowers `$arr['k'] = $v` to an `ArrayDimFetch` whose *result temporary*
is then assigned, and a later read of the same key produces a different
temporary with no SSA link back. Tracking per-key taint would mean a separate
map keyed by (array operand, constant key), which does not help the moment the
key is dynamic.

**Direction:** over-approximating, so this produces false positives, not false
negatives.

### Object properties are per class, not per instance

`Foo::$value` is one slot. Taint written to `$this->value` in any instance of
`Foo` is visible from every read of `$value` on any `Foo`.

**Direction:** over-approximating.

### Dynamic calls are not followed

```php
$callback = $_GET['action'] === 'x' ? 'render_x' : 'render_y';
$callback( $value );        // unresolved
call_user_func( $fn, $v );  // unresolved
```

A closure assigned to a variable *is* followed, through assignments. Everything
else — a variable function name, `call_user_func()` with a variable callee, a
variable method name — is left unresolved, marked imprecise, and its return
value treated as clean.

**Direction:** under-approximating. This is the biggest source of false
negatives in the tool. `--assume-dynamic-tainted` flips it: every unresolved
call propagates all taint from its arguments, which is noisy but gives an upper
bound on what might be missing. That is exactly what you want when auditing the
auditor.

### `include` and `require` are not followed

A template file included at runtime is analysed as its own file, but the
variables in scope at the include site do not flow into it, and vice versa.

```php
$title = $_GET['title'];
include 'template.php';     // template.php echoing $title is not connected
```

This is the classic WordPress theme shape and it is a real gap. Following it
properly needs include-path resolution and a scope model, which is a
disproportionate amount of machinery for a v1.

**Direction:** under-approximating.

### Filter and action callbacks are not followed

`apply_filters( 'the_content', $value )` is modelled as a pass-through: the
value goes in and comes out. Callbacks registered on that filter elsewhere are
not analysed as part of the flow, so a callback that *introduces* taint is
invisible, and one that sanitises is not credited.

`add_action( 'wp_ajax_*', ... )` **is** resolved, but only by the AJAX
authorization rule, and only for the four callback shapes below. Unresolved
registrations are counted and reported rather than ignored.

**Direction:** both. Under-approximating for taint-introducing callbacks,
over-approximating for sanitising ones.

### Hook callbacks resolve in four shapes only

`'function_name'`, `[$this, 'method']`, `[__CLASS__, 'method']` /
`[self::class, 'method']`, and an inline closure or arrow function. A callback
built any other way is reported in the "hook registrations could not be
resolved" count so the gap is visible.

### An unmodelled function returns clean

A call to something the catalogue does not know and the scan cannot see —
a function from another plugin, a Composer dependency outside the scan path —
returns untainted.

Treating unknown returns as tainted would be correct and unusable: every
`wp_something()` not yet in the registry would light up.

**Direction:** under-approximating. The fix is to add the function to the
registry, which is a TOML edit, not a code change.

### References are not aliased

```php
function fill( array &$out ) { $out[] = $_GET['x']; }

$values = [];
fill( $values );
echo $values[0];   // not reported
```

By-reference parameters are analysed as ordinary parameters. The write to the
caller's variable is not modelled.

**Direction:** under-approximating.

### `wp_json_encode()` context-sensitivity is approximated

Modelled as clearing `html`, which is true inside a `<script>` JSON context and
false in general. Marked imprecise.

### Loops are analysed to a fixed point, not unrolled

A value tainted only on the third iteration is tainted from the first as far as
the analysis is concerned. Phi nodes union across every path.

**Direction:** over-approximating.

---

## Structural rules

### `permission_callback` is checked for presence, not for adequacy

A route with `'permission_callback' => 'acme_check'` passes, whatever
`acme_check()` actually does. Only a literally absent callback, or
`__return_true` on a write route, is reported.

### The AJAX rule accepts anything that reads like a check

Alongside the real WordPress functions, a method call whose name contains `can`,
`capab`, `permission`, `nonce`, `referer`, `authori`, `authenticat` or `verify`
is accepted as a check.

Without that, every codebase that factors its checks into a helper gets a false
positive — and a false positive on an authorization rule is exactly the kind
that gets a tool muted. The cost is that `$this->can_haz_cheeseburger()` also
satisfies it.

### `register_rest_route()` options must be an inline array

A route whose options come from a variable or a method call is counted as
unresolved rather than reported.

---

## Parsing

### Six modern constructs are lowered before analysis

`ircmaxell/php-cfg` v0.8.1 cannot parse `match`, `?->`, `enum`, first-class
callables (`f(...)`), intersection types, or `yield from`, and throws on
`static $x;` with no initialiser. `Cfg\CompatibilityVisitor` rewrites all seven
into equivalent older syntax first. See `docs/php-cfg-api-notes.md`.

Every rewrite is semantics-preserving *for taint purposes*, which is weaker than
being semantics-preserving in general:

- **`match`** becomes a ternary chain. A `match` with no arm and no default
  throws `UnhandledMatchError`; the ternary yields the last arm instead. The
  subject expression is repeated once per arm, so a subject with side effects is
  analysed several times — findings de-duplicate, so this costs work rather than
  output.
- **`yield from $inner`** becomes `yield $inner`. Different values are yielded;
  the same data flows.
- **`A&B`** becomes `A`. The declared type is used only to resolve a method
  call's receiver, and any member of the intersection answers that.
- **`$o?->m()`** becomes `$o->m()`. They differ only in short-circuiting on
  null, which carries no taint.

### `eval`'d and generated code is not analysed

Naturally. If a plugin builds PHP at runtime, whatever it builds is invisible.

---

## Scope

### Analysis is whole-program, and a plugin is the natural unit

Interprocedural taint crosses files, so every file in the scan is parsed and
held in memory before any analysis runs. Scanning several unrelated plugins as a
single program is neither realistic nor cheap — point wp-taint at one plugin or
theme at a time.

Cross-file flows within the scan path are followed. Flows into code outside it
are not.

### Duplicate function declarations: first wins

If the scanned tree declares the same function twice — a conditionally-defined
shim, a vendored copy — the first in sorted file order is the one summarised.
Deterministic, but it may be the wrong one.

### The result cache is all-or-nothing

Because the analysis is whole-program, the only sound cache unit is the whole
scan. Changing one file invalidates it. Caching a single file's findings would
be wrong the moment a function it calls changed elsewhere.

---

### `--jobs` needs `pcntl`

Parallelism forks after parsing, so children inherit the parsed CFGs through
copy-on-write. Without the `pcntl` extension — which is CLI-only and absent on
some hosts — `--jobs` silently falls back to serial. The output is identical
either way; only the wall clock changes.

Parsing stays serial: it is the phase that builds the shared function table, and
it is cheap relative to the analysis. Expect roughly a 2x improvement rather
than a linear one.

## Not implemented

- **HTML reporter.** Deferred post-v1; the deployment context is a developer
  machine, where console, JSON and SARIF cover it.
- **Second-order flows through the database.** `update_option()` writing tainted
  data and `get_option()` reading it are both modelled, but as independent
  source and sink, not as a connected flow through a specific option key.
