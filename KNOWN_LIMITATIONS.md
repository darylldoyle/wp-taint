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

### Array element taint is per-key when both ends name a constant key

```php
$context = [];
$context['title'] = $_GET['title'];
$context['id']    = 42;

echo $context['id'];      // not reported
echo $context['title'];   // reported
```

A write with a literal key goes to a slot of its own, and a read naming that key
sees only what went into it.

**It stops helping the moment either end is dynamic.** A write with a computed
key could land anywhere, so it goes to the whole-array slot; a read with a
computed key could be any key, so it sees everything, including every per-key
slot. Both are what the analysis did for all arrays before, and both are still
the fallback.

**Direction:** over-approximating at the dynamic ends, exact in the middle.

### Object properties are per class, not per instance

`Foo::$value` is one slot. Taint written to `$this->value` in any instance of
`Foo` is visible from every read of `$value` on any `Foo`.

The trace does reach back to the source: the map records the trace of the write
that tainted a property, and a read splices it in ahead of its own step. Without
that, roughly a fifth of corpus findings had traces that began "read from
property `$x`" and stopped, which is not something a reviewer can act on.

**Direction:** over-approximating.

### Unknown provenance is reported only on request

The engine has three answers for a value now — tainted, clean, and *unknown*.
The third is new, and it is off unless `--unknown-provenance` is passed.

A parameter of a function nothing in the scan calls, or the result of a callee
that cannot be followed, used to count as clean. That is a documented false
negative, taken on the grounds that an undocumented false positive is worse. It
costs more than it looked: a third-party suite scores the output half of this
tool at **0.18 recall** on exactly that shape, and turning the flag on takes it
to 0.82.

Off by default because it changes the question. Off, the tool answers "can I
trace this value to something dangerous". On, it answers "is this value proven
safe", which is what WordPress's own sanitise-on-input, escape-on-output
standard actually asks — and which produces 926 more findings across the fifty
corpus plugins, at `low` severity.

Neither question is wrong. The flag says which one is being asked.

### Escaping is judged against the context it lands in

An escaper being present is not the same as it being the right one:

```php
echo '<script>var x = "' . esc_html( $v ) . '";</script>';   // ";alert(1);//
printf( '<a href="%s">x</a>', esc_attr( $url ) );            // javascript:...
printf( '<div data-v=%s></div>', esc_html( $v ) );           // x onmouseover=
```

This is a structural rule, not a dataflow one, because the context belongs to
the literal text around the hole rather than to the value: `esc_attr()` is right
in a quoted attribute, wrong in an `href`, and wrong again in an unquoted one.

**What it will not judge.** A context built from a variable, a `printf` with
positional `%1$s` specifiers, or a call it does not recognise as an escaper.
`wp_get_referer()` is a source, and accusing it of being the wrong escaper both
misnames the problem and duplicates the rule that already has it.

**What it will say that some will disagree with.** `esc_url_raw()` in an
attribute is reported. It is documented — by WordPress and by this catalogue —
as being for storage and redirects rather than output, and WPCS rejects it for
output too. WP Super Cache uses it in 32 form actions, which is why one pinned
plugin moved from 9 findings to 41.

### Escaping must survive to the point of output

Escaping is called *late* escaping because it has to be the last thing that
happens to a value. Anything afterwards is another chance to undo it:

```php
$title = esc_html( $_GET['title'] );
echo apply_filters( 'acme_title', $title );   // any plugin may rewrite this
echo wp_trim_words( $title, 20 );             // 'wp_trim_words' runs inside
```

A plain taint model sees the escaper clear the taint and nothing put it back, so
it reports neither. An escaper now marks its result, a call that hands the value
to a third party trades that mark for `escape_voided`, and the output construct
reports it under its own rule at medium — one band below never having escaped at
all, because it needs a second plugin to actually hook the filter.

**Which calls void it is generated, not guessed.**
`tools/generate-filterable-catalogue.php` parses a WordPress checkout and lists
every function whose *return value* has been through `apply_filters()`, by
running a small fixed point over each body: a variable is filtered if it is
assigned from a filter or from anything mentioning an already-filtered variable.
Of 4,272 core functions, 933 mention a filter and **629 return one**. Naming
heuristics — anything starting `wp_` or `get_` — would have been a guess.

**Escaping after the filter clears the voiding**, because that is the correct
order: `wp_kses_post( apply_filters( 'x', esc_html( $v ) ) )` is safe however the
filter behaves.

**Two deliberate exceptions.**

- **Registered escapers never void.** Core ends `esc_html()` with
  `return apply_filters( 'esc_html', $safe_text, $text )`, so the generated list
  contains it. Acting on that literally makes every escaper void its own work.
  A site with a hostile `esc_html` filter has a problem this rule cannot
  usefully report at each of ten thousand call sites.
- **Numeric coercion does not mark a value escaped.** `absint()` clears every
  kind, but coercing an id to an integer is not escaping content, and treating
  it as such made `echo get_the_title( absint( $_GET['id'] ) )` look like voided
  escaping because the *id* carried the marker into a call whose result has
  nothing to do with it.

**The list records which parameter the filtered value comes from**, because
"any escaped argument voids the result" is wrong in a way the corpus found
immediately:

```php
$comment['comment_author_url'] = esc_url( $_POST['url'] );
print( wp_update_comment( $comment ) );   // returns a row count, not the URL
```

`get_the_title( $id )` filters a title it fetched itself, so an escaped `$id`
never reaches the output. Only the parameters the filtered return actually
derives from can void anything.

**Known false positive.** `wp_update_comment()` is listed as returning its first
parameter filtered, because core contains:

```php
$data = apply_filters( 'wp_update_comment_data', $data, $comment, $commentarr );

if ( false === $data ) {
    return $data;
}
```

That `return` is only reachable when `$data` is `false`, so the function never
actually hands back the filtered string. Knowing that needs path-sensitivity,
which a generated list cannot have. It costs one finding on Akismet — the plugin
pinned to zero specifically to catch this kind of thing, which is the system
working even though the answer is wrong.

**What is still missed.** Pluggable functions, which a plugin may redefine
outright rather than filter. And a filter reached inside a function whose body
the scan cannot see.

### Stored object injection is a separate, lower severity

`unserialize()` on data from an option, post meta or a database row instantiates
whatever was stored there, so a POP chain in the loaded code runs. Three of the
pinned CVEs are exactly this, and the classic WordPress escalation is a
subscriber-level meta write turning into RCE.

It carries its own kind and its own rule at **high** rather than critical,
because it needs a precondition the engine cannot check: an attacker who can
write that store first. Reporting 91 corpus findings as critical alongside the
12 that need no precondition at all would devalue the word for both.

`unserialize( $data, [ 'allowed_classes' => false ] )` is not reported. That is
the documented fix for the class — it is what Better Search Replace shipped for
CVE-2023-6933 — and flagging code that already applies it would be telling
people to do what they have done. The options array is read at the call site
only; a value built elsewhere counts as permitting objects, because being wrong
in the permissive direction would hide the bug.

Deliberately *not* extended to `path` or `url`: an attacker who can write an
option already has the access those sinks would give them. Object injection is
different because it grants more than the write did.

### `esc_sql()` is only credited inside quotes

`esc_sql()`, `wpdb::_real_escape()` and `like_escape()` escape quotes and
backslashes. Inside quotes that is a real defence; outside them there is nothing
to escape and `1 OR 1=1` reaches the database whole. So they do not clear `sql`;
they trade it for `sql_unquoted`, which the sink reports only when the value
lands in an unquoted position.

Quote state is read from the literal fragments of the query string, counting
unescaped `'` and `"`. Backticks quote identifiers rather than values and offer
a value no protection, so they deliberately do not count as being in quotes.

**What is missed.** A query whose quoting is itself computed, and any case where
the string is not built where the sink is — the value has to reach a sink whose
query is a concatenation or an interpolation for the position to be readable at
all.

### Stored sources carry HTML and SQL taint only, not path or url

`get_option()`, `get_post_meta()` and the rest are modelled as introducing
`html`, `html_attr` and `sql`. They are deliberately **not** modelled as
introducing `path` or `url`.

Stored XSS and second-order SQL injection are real and common. "An option holds
a directory name, therefore every `unlink()` downstream is path traversal" is
not: an attacker who can write arbitrary options already has the access those
sinks would give them. Modelling it that way produced several hundred findings
on the corpus with no plausible attack behind any of them.

**Direction:** under-approximating, deliberately. If a codebase really does let
a low-privilege user write a path into an option, add a project-local
`[[sources]]` entry with `kinds = ["path"]`.

### Dynamic calls are followed as far as the value can be traced

```php
$callback = $_GET['action'] === 'x' ? 'render_x' : 'render_y';
$callback( $value );                       // both, unioned
call_user_func( array( $this, 'run' ), $v ); // resolved
array_map( 'esc_html', $items );             // a real sanitizer application
```

What resolves: a callable that traces back to a literal string, a phi of
literals, a concatenation of resolvable parts, an `array( $object, 'method' )`
pair, a class-name pair, a closure, or an object with `__invoke`. Calls made on
your behalf by `call_user_func()`, `call_user_func_array()`, `array_map()`,
`usort()` and the rest resolve to the callee, not to the dispatcher; the list
lives under `[[dispatchers]]` in the catalogue, so a project can add its own.
A callable that resolves to several names reaches all of them and the effects
are unioned, because picking one would be a guess.

What does not: a callable arriving as a parameter, read from a property, or
returned by a call the engine cannot see into. A name that resolves to a
function nobody can find a body for also counts as unresolved, rather than
resolving to nothing and reporting clean.

**Direction:** configurable, because there is no correct answer — only a choice
about which way to be wrong.

| `--dynamic-calls` | An unresolved call | Wrong when |
| --- | --- | --- |
| `clean` | returns nothing tainted | the callee passes its arguments through |
| `propagate` *(default)* | passes its arguments to its return value | the callee escapes them |
| `tainted` | returns everything tainted | almost always, deliberately |

`propagate` is the default because an unresolved callee is nearly always code
in the same project, and code in the same project transforms its arguments
rather than conjuring request data out of nothing. `tainted` is the upper bound
on what the engine might be missing — noisy on purpose, and the right setting
when auditing the auditor. Every finding produced under an assumption is marked
`imprecise` so it can be filtered back out.

`--assume-dynamic-tainted` is the old spelling of `--dynamic-calls=tainted` and
still works.

### `include` and `require` are followed

```php
$title = $_GET['title'];
include __DIR__ . '/parts/header.php';   // header.php echoing $title is connected
require ACME_DIR . 'config.php';         // and what config.php assigns comes back
```

Paths are folded from literals, `__DIR__`/`__FILE__`, constants declared anywhere
in the scan, and the pure path helpers WordPress builds them with — `dirname()`,
`untrailingslashit()`, `plugin_dir_path()` and friends. A resolved path is looked
up in the set of files being scanned rather than on disk, so two machines with
the same checkout resolve the same set.

Scopes join both ways, and converge in the interprocedural loop alongside the
property map. Cycles terminate because the return direction reads the table
rather than descending.

**What is still missed.** An include whose path will not fold — about half the
sites in the corpus — is counted rather than followed. `get_template_part()`,
`load_template()` and `locate_template()` are not resolved through the template
hierarchy yet. And the include path itself is not modelled: PHP would search it
before the calling file's directory, but that is runtime configuration the
analysis cannot see.

**Direction:** under-approximating at the unresolved paths, over-approximating at
the resolved ones — a file's inbound scope is unioned over every site that
includes it, so a template included from two places sees either caller's state.

`--no-follow-includes` turns the whole thing off.

### Filter and action callbacks are followed

`apply_filters( 'the_content', $value )` is a call to every callback registered
on `the_content`, and `do_action( 'acme_saved', $note )` flows its arguments
into each callback's parameters. A callback that introduces taint taints the
filter's result; one that sanitises is credited.

The graph is built from `add_action()` and `add_filter()` across the whole scan,
so a callback registered in one file and defined in another connects. Hook names
resolve through the value resolver, so `"wp_ajax_{$action}"` and
`__NAMESPACE__ . '\\render'` both work. Priority is recorded for the trace text
and otherwise ignored: it cannot change a union.

Which dispatchers are followed is data, under `[[dispatchers]]` with
`hook = true`. `apply_filters`, `apply_filters_ref_array`, `do_action` and
`do_action_ref_array` ship; a project with its own dispatcher adds it there.

**What is still missed.** A registration whose hook *name* will not resolve is
not connected to anything. It is listed in the unresolved-hook count rather than
unioned into every dispatch — that would be the sound choice and it is the wrong
one, because a plugin with 22 unplaced registrations against 201 hooks would gain
22 spurious callees on every dispatch. `remove_filter()` is not modelled either,
so a callback removed at runtime is still analysed.

**Direction:** under-approximating, at the unresolved names.

### Hook callbacks resolve in every form PHP accepts

`'function_name'`, `'Class::method'`, `array( $object, 'method' )`,
`array( 'Class', 'method' )`, a closure, an arrow function, and an object with
`__invoke`. Resolution runs through the same resolver the rest of the analysis
uses, so a hook edge and a `call_user_func()` edge cannot disagree about what a
callback means.

A callback the resolver cannot pin down is reported in the "hook registrations
could not be resolved" count so the gap stays visible.

### An unmodelled function returns clean

A call to something the catalogue does not know and the scan cannot see — a
function from another plugin, a Composer dependency outside the scan path —
returns untainted.

Treating unknown returns as tainted would be correct and unusable: every
`wp_something()` not yet in the registry would light up.

**Direction:** under-approximating. Two fixes: add the function to the registry,
which is a TOML edit rather than a code change; or point `--include-path` at the
tree it lives in.

### `--include-path` at WordPress core is opt-in

```bash
wp-taint scan ./src --include-path=./vendor --include-path=/path/to/wordpress
```

Files under an include path are parsed and summarised so their symbols exist and
their taint behaviour is known, but findings inside them are never reported —
neither dataflow nor structural, because a missing `permission_callback` in
WordPress core is not your bug.

Pointing it at a Composer dependency is straightforwardly useful. Pointing it at
core has been triaged once and is much better than it was — Akismet is back to
zero findings with 786 core files referenced — but it is still a larger change
than it looks, and every class found so far was a *catalogue* gap rather than an
engine fault:

- `_n()` ends in `apply_filters( 'ngettext', … , $number, … )`, so with the hook
  graph following that filter the number could reach the return.
- `add_query_arg()` reads the current request only when no base URI was passed.
- `get_avatar()` returns markup it escaped itself.
- `$wpdb->prefix` is assigned by `wpdb::get_blog_prefix()`, so analysing core
  made the identifier every plugin interpolates into SQL look tainted.

Expect to find more of those, and expect the fix to be a catalogue entry. The
flag is off unless you ask for it, and a baseline is a reasonable first step on
a large codebase.

### References are followed

```php
function fill( array &$out ) { $out[] = $_GET['x']; }

$values = [];
fill( $values );
echo $values[0];                          // reported

preg_match( '/(\d+)/', $_GET['q'], $m );  // reported
parse_str( $_SERVER['QUERY_STRING'], $q ); // reported

$sink = &$values;                          // aliased
foreach ( $items as &$item ) { … }         // aliased
```

Three mechanisms. A `[[byref]]` catalogue section covers the built-ins that
write through an argument. `FunctionSummary` carries `paramToParam` and
`sourcesToParam`, so a user function's out-parameters are applied back onto the
caller's arguments — the first intersected with what the caller actually passed,
so a parameter that only ever carries HTML does not hand back SQL. And an alias
pass unions taint across the pairs that `$a = &$b` and by-reference `foreach`
create.

Everything here only ever *adds*. SSA gives a by-reference write no operand of
its own, so the caller's argument is the slot, shared with whatever else writes
that variable; only growing keeps the fixed point monotone.

**Direction:** over-approximating, in two places. A call that genuinely
overwrites its argument with something clean cannot be modelled as clearing it.
And a variable aliased anywhere in a function is treated as aliased throughout
it, rather than only after the binding.

### `wp_json_encode()` context-sensitivity is approximated

Modelled as clearing `html`, which is true inside a `<script>` JSON context and
false in general. Marked imprecise.

### Loops are analysed to a fixed point, not unrolled

A value tainted only on the third iteration is tainted from the first as far as
the analysis is concerned. Phi nodes union across every path.

**Direction:** over-approximating.

---

## Structural rules

### `permission_callback` is checked for what it reaches

Three distinct problems, at three severities:

| Reported | Severity |
| --- | --- |
| No `permission_callback` at all | high |
| `__return_true` on a write route | critical |
| A callback that reaches no authorization check | medium |

The third walks the call graph from the callback looking for one of the
`[[authorization]]` primitives. It is deliberately the quietest of the three,
and stays silent whenever the walk was incomplete: a callback that cannot be
resolved, or whose subgraph runs into something the engine cannot follow, is not
reported at all. A callback can be doing something legitimate we cannot see.

### The AJAX rule asks what the callback reaches

Walking the call graph from the resolved callback, to a depth of six, looking for
a call to one of the `[[authorization]]` primitives — `current_user_can`,
`check_ajax_referer`, `wp_verify_nonce` and the rest. Recursing through helpers
is what credits `acf_verify_ajax()` for the right reason: it calls
`wp_verify_nonce`, and we can see that.

The name heuristic this replaced accepted any call containing `can`, `capab`,
`permission`, `nonce`, `referer`, `authori`, `authenticat` or `verify`. It
survives only where the graph cannot speak — a callback that will not resolve, or
a walk that ran into something unfollowable — and findings resting on it are
marked `imprecise`.

**What is still missed.** A check reached only through a dynamic call the engine
cannot resolve. Those walks report themselves incomplete, so the finding is
marked rather than suppressed.

### Hooks registered through a wrapper are followed, by name

Boilerplate-generated plugins do not call `add_action()` where a scanner can see
it. They collect registrations on a loader and replay them later, and three arg
layouts cover what the corpus contains:

```php
$this->loader->add_action( 'wp_ajax_x', $component, 'method' );  // WPPB
$this->add_action( 'wp_ajax_x', array( $this, 'method' ) );      // wrapped array
$this->add_action( 'wp_ajax_x', 'method' );                      // method on $this
```

A method named `add_action` or `add_filter` counts as a registration whatever
its receiver, because every plugin names its loader differently and the method
name is the only stable signal. This applies to the hook graph as well as the
authorization rules, so taint now crosses a wrapped filter.

Eight of the fifty corpus plugins register this way, and until this existed none
of those registrations were seen at all — not resolved, not reported unresolved,
simply absent, which made a clean authorization report on a boilerplate plugin
meaningless.

**What is still missed.** The component's class, when it is neither `$this` nor
a variable assigned from a single `new` in the same file. The boilerplate always
constructs it locally, so the common case resolves; anything else is reported
unresolved rather than guessed.

### A nonce satisfies the AJAX rule but not the admin-post one

A nonce proves the request was deliberate; it says nothing about entitlement,
and a subscriber can hold a valid nonce for a form they should never submit. So
`[[authorization]]` entries carry `proves = "entitlement" | "intent"`.

The admin-post rule requires entitlement, which is the correct bar. The AJAX
rule accepts either, which is not — it is the pragmatic floor, because AJAX
handlers overwhelmingly guard with `check_ajax_referer()` alone and demanding a
capability as well would bury the real findings under every plugin in the
corpus.

### An option name assembled out of sight is assumed to be anchored

`update_option()` is reported when the option *name* comes from the request,
because naming the option is the whole attack: `default_role` is an option and
`administrator` is a legal value for it. Any fixed fragment in the name — head,
tail or middle — pens the attacker into a namespace the plugin already owns, and
is not reported.

That fragment is often several frames away, so the check follows function
summaries and property writes to find it. Two gaps remain, both deliberate:

- **An unresolvable callee is assumed to anchor.** A helper that returns the
  request verbatim through a call the engine cannot follow is not reported.
- **Anchoring is not propagated from a caller into a parameter.**
  `new Thing( $_POST['name'] )` stored on a property and later written is
  missed, because the constructor cannot see what its caller passed.

Also unmodelled: an allowlist gate. WooCommerce validates with
`in_array( $setting_id, $valid_setting_ids, true )` and `continue`, which makes
the write safe with no literal anywhere in the name. Recognising that needs the
guard's branch, and would be this engine's first path-sensitive analysis.

### `register_rest_route()` options are folded, not traced

Options handed in through a variable assigned exactly once from a literal, or
returned by a function whose only `return` is a literal, resolve. Anything built
conditionally, appended to, or passed through a filter does not, and is counted
as unresolved rather than guessed at.

That is deliberately a constant fold and not a dataflow analysis: a wrong answer
in this rule is an authorization bypass either reported or missed.

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
