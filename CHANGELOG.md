# Changelog

All notable changes to wp-taint are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--memory-budget` and the `memory_budget` project option cap the memory held
  by parsed files, at 4GB by default. The scan used to hold every file's control
  flow graph from parsing to the end. It now keeps a table of what each function
  is, and up to the budget of parsed files. A file it cannot hold is parsed again
  whenever one of its functions is needed. That costs time and changes no
  finding. `unlimited` holds every file, as before. `--debug-memory` reports how
  much the cache holds and how many files it rebuilt.
  See docs/design/two-pass-engine.md.
- `tools/compare-budget.php` scans each target with no budget and with one, and
  reports any difference in findings, traces or warnings.
- `--debug-memory` prints PHP's heap in use, the peak so far and the elapsed
  time at every phase and every fixed-point round, in place of the progress
  bar. The operating system's figures are no use for this on macOS, which
  compresses and swaps a large scan until its resident size is a small fraction
  of what PHP holds.
- `tools/compare-incremental.php` scans each target with incremental rounds
  on and off and reports any difference in findings, traces or warnings.
- `tools/compare-simplifier.php` builds every file with both php-cfg's
  simplifier and wp-taint's, and reports any graph that differs other than by
  wp-taint's leaving fewer references to a removed phi.
- A `notice` severity, below `low`, for a finding the author acknowledged with
  a matching `phpcs:ignore`. A line-specific ignore naming the sniff a rule maps
  to (`WordPress.Security.EscapeOutput.OutputNotEscaped` for the output rules,
  `WordPress.DB.PreparedSQL.*` for the SQL ones) is the author saying they
  looked, so the finding is reported as a notice rather than silenced, with the
  sniff and their reason in its trace. It never fails a build. A bare
  `phpcs:ignore`, an unrelated sniff, and `phpcs:disable`/`enable` ranges are
  deliberately not honoured. `--no-phpcs-suppressions` turns the behaviour off,
  for auditing code whose author's judgement you do not share.
- Object-level authorization detection, the largest previously-silent class in
  the authorization column.
  - `wp.authz.object-id-from-request` reports a request-chosen post, comment,
    term or user id reaching an object operation (`wp_delete_post()`,
    `update_user_meta()`, `wp_set_password()` and their relatives) when no
    check dominating the sink entitles the caller to that object. This is the
    classic WordPress IDOR (CWE-639): the check is present and correctly named,
    but scoped to a role rather than the row. A new `object_id` taint kind
    carries the id and, unlike every payload kind, survives `absint()`,
    `intval()`, `(int)` and `is_numeric()`, because coercing an id to an integer
    proves nothing about whose row it names. The finding is discharged by an
    object-scoped meta capability with the id in hand, or a site-wide grant,
    read off the dominating branch by the new `CapabilityGuard`.
  - `wp.authz.meta-cap-without-object` reports a meta capability (`edit_post`,
    `delete_user`, …) checked with no object id, which resolves against no row
    and so authorizes nothing about the object being operated on.
- A `[[capabilities]]` registry section classifying core capabilities as
  `object`, `site` or `role`, so the scope decision is data rather than code. A
  capability the catalogue does not know is treated as site-scoped.
- A sink for the `html_attr` taint kind, `wp.xss.unescaped-attribute`, closing
  the biggest documented false-negative class. `sanitize_text_field()` strips
  tags and leaves both quote characters, yet it used to clear `html` and
  `html_attr` together and so was credited as an output escaper:
  `value="<?php echo $sanitised ?>"` was silent while `" onmouseover=… x="`
  walked straight out of the attribute. The catalogue now tells the truth per
  function: the tag-strippers (`sanitize_text_field()`,
  `sanitize_textarea_field()`) stop clearing `html_attr`; the `esc_html()`
  family and `esc_textarea()` start, because `ENT_QUOTES` encodes both quotes;
  the `wp_kses()` family keeps passing it through, since it passes markup and
  its quotes with it. The new rule fires when a component carrying `html_attr`
  without `html` lands inside a quoted attribute, read off the literal fragments
  the way the SQL shape check reads quote position. Raw values stay the `html`
  sink's, so nothing reports twice, and where this rule and the structural
  context rule land on the same line the traced finding wins.
- Second-order flow through option keys. `update_option( 'k', $_POST['x'] )` in
  one function and `get_option( 'k' )` in another were modelled as independent (a
  stored source here, a storage sink there), so the flow read only as "an option
  might hold anything" and `include get_option( … )` was not reported at all. The
  options table is now one more property owner: a read of a key the scan watched
  being written unions the write's full kinds on top of the stored baseline and
  splices the write into the trace, so a proven flow with both ends visible is
  followed the whole way. Post meta and user meta stay unconnected per key, and
  say so in KNOWN_LIMITATIONS.
- Inherited-method call resolution. Method lookup was flat (`Class::method`
  exactly as written), so a method inherited from a parent or brought in by a
  trait never resolved, and everything it returned was unaccounted for. A new
  project-wide `ClassHierarchy` index records who extends whom and who uses
  which trait, and lookup now follows PHP's own precedence: the class, its
  traits, the parent, the parent's traits, and on up. `parent::` starts one
  level up instead of collapsing to the calling class, so it dispatches past
  an override to the body PHP would actually run. Static calls, instance
  calls, constructors, callables (`'Class::method'`, `array( $this, 'method' )`),
  `__invoke`, hook callbacks and the structural rules' call-graph walks all
  resolve through it. Gravity Forms is the everyday case: `RGFormsModel
  extends GFFormsModel` with the table-name helpers on the parent meant every
  `RGFormsModel::get_lead_meta_table_name()` interpolation was reported as a
  query built from a value the engine could not see; it now resolves to
  `$wpdb->prefix . 'rg_lead_meta'` and is accounted for. Trait `insteadof`
  conflict resolution is not modelled, and a parent that is neither scanned
  nor referenced still ends the walk unresolved rather than guessed at.
- Properties follow the same hierarchy. A typed or constructor-assigned
  property declared on the base class resolves through the subclass
  (`protected Acme_DB $db` on the parent, `$this->db->table_name()` in the
  child), a `self`-typed property (and `$this->x = new self()`) resolves to
  its declaring class, and stored property taint is unioned across the chain,
  because the property is one storage slot on the instance whichever class's
  method wrote it. That last one fixes a false negative: `$this->value =
  $_GET['x']` in a base-class constructor, echoed by a subclass method, was
  invisible under flat per-class keys.
- The hierarchy walk continues into a referenced tree, so `--include-path`
  pointed at WordPress core now makes `extends WP_List_Table` (and every other
  core base class) resolve to core's body: inherited helpers are accounted
  for, and taint through an inherited core method still lands as a finding in
  the scanned file.

### Fixed

- `$request['id']` is read as the REST parameter it is. `WP_REST_Request`
  implements ArrayAccess over its parameters, and the array form was not a
  source at all, so the commonest way to read a REST parameter reached a sink
  as a parameter of unknown origin, at `low`.
- REST parameter accessors carry every request kind `$_GET` does. `object_id`
  and `csv` were added to the superglobals and never reached the REST
  accessors, and `ldap` and `xpath` never had, so `wp_delete_post(
  $request->get_param( 'id' ) )` reported nothing. The raw body,
  `get_body()` and `php://input`, carries the same set. A test now holds every
  whole-request source to `$_GET`'s kinds.
- An unresolved callee is assumed to write back where it could: into any
  variable passed to it, and into and out of its receiver, when nothing about it
  can be seen. `$cb( $_GET['a'], $out ); echo $out;` reported nothing. Where
  the scan can say what the callee might be, it does: a named method on an
  untyped receiver is one of the methods of that name, and a computed name on a
  receiver of known class, `$this->{ 'validate_' . $type }( … )`, is one of that
  class's methods, so only a position one of them takes by reference is
  written back. A dispatcher such as `call_user_func()` passes copies and
  writes back nothing.
- A strict `in_array()` against an allowlist held in a variable is credited as
  a guard. Only a list written inline in the call counted, so `$allowed =
  array( … ); if ( ! in_array( $name, $allowed, true ) ) return;` left
  `update_option( $name, … )` reported as an arbitrary option write.

- A callback registered as `array( $this, 'method' )` in a base class reaches
  every subclass override. `$this` is whatever class the object really is, so a
  base that registers the callback in its constructor runs the child's method
  when the child is constructed. The callback resolved only to the base's body,
  so a child that printed its argument unescaped reported the `low`
  unknown-input finding in place of the high one, and a callback on an abstract
  method did not resolve at all. The callable now resolves to the base's body
  and to every override the scan declared, read from the class hierarchy. The
  same applies to `array( 'static', 'method' )`, to a trait's `$this`, and to
  the plain dispatchers such as `call_user_func()`. A receiver whose class is
  known exactly is not widened, and a direct `$this->method()` call is
  unchanged. On the pinned corpus this adds one finding to WPForms Lite:
  `WPForms_Provider` registers `array( $this, 'process_entry' )` with an empty
  body, and the Constant Contact subclass's override is what runs.
- A filter callback is no longer credited as a sanitiser.
  `add_filter( 'acme_label', 'esc_html' )` made
  `echo apply_filters( 'acme_label', $_GET['a'] )` report nothing, because a
  callback found on the hook replaced the filter's own result. The scan cannot
  know which callbacks are on a hook when it fires. A registration can sit
  behind a condition, `remove_filter()` can take it off, and code outside the
  scan can add or remove callbacks. `apply_filters()` and
  `apply_filters_ref_array()` now always pass the value handed in through to
  the result, and each callback's return is added on top. Two consequences
  follow. A value escaped before a filter with a registered callback now
  reports `wp.xss.escape-voided`, the same as with nothing on the hook. And a
  union of callees no longer reports escaping as voided when no single callee
  both escaped the value and filtered it, the rule a branch merge already
  followed. `call_user_func()`, `array_map()` and the other plain dispatchers
  still credit the callable they run. The fixture
  `safe/hook-filter-callback-escapes` encoded the old behaviour and moved to
  `vulnerable/hook-filter-callback-escaping-not-credited`. The pinned corpus
  does not move. The analyser-fixtures suite improves from 6 missing and 7
  unexpected to 4 and 5: F14 and F15 now report the escape-invalidated finding
  their authors label, in place of plain unescaped output.
- A value passed down through more than one call to a sink is reported. A
  summary never handed its callees' sinks on to its own callers, so
  `top( $_POST ) → mid( $v ) → leaf( $v ) → echo` reported nothing: not even
  the `low` unknown-input finding, because every function in the chain had a
  caller. Values returned upward were unaffected. On the pinned corpus this
  adds one finding, a correctly traced four-call flow in Loginizer's bundled
  LightOpenID from `$_POST['openid_claimed_id']` to `file_get_contents()`.
- Call chains of any depth resolve. Functions were summarised in key order,
  so a chain whose callers sort before their callees moved one level per
  round, and the 32-round cap stopped it at 31 levels with only a
  non-convergence warning. They are now summarised callees first (Tarjan's
  strongly connected components over the call graph), and a round's work is
  split into contiguous slices of that order, so `--jobs` no longer strips a
  chain across workers. Tested to 250 levels in both directions and with four
  workers.
- A scanned hook callback fed by a `do_action()` in a referenced tree is
  reported. The plugin's dispatch made it the callback's caller, so the
  callback's parameters were not seeded as unknown, and the flow was found only
  while analysing the plugin, which the findings pass skipped: referencing a
  plugin made the finding disappear. Reference functions that call into the
  scanned code are now analysed in the findings pass, and only findings that
  land in scanned code are kept.

Four precision fixes from adjudicating every finding of a Gravity Forms scan
(92 findings: 0 exploitable, 75 correct catches, 17 false positives; the fixes
below remove 10 of the 17).

- `wp.xss.wrong-context-escape` findings now carry `kind: html`, not
  `kind: authz`. The rule shared a structural-finding helper built for the
  authorization rules and inherited its kind.
- A non-literal `$wpdb->prepare()` format string no longer launders the
  template's failure onto its bound arguments. prepare() substitutes and
  escapes every `%s`/`%d`/`%i` argument whether or not the template was
  literal, so a request value bound to a placeholder no longer re-reports the
  outer `$wpdb->query()` as an unprepared sink. The non-literal template is
  still reported as `wp.sqli.prepare-non-literal`.
- `wp.xss.wrong-context-escape` no longer reports three escapes that cannot
  break out of any context:
  - `absint()`/`intval()` anywhere: an integer carries no breakout, including
    in a URL attribute where `esc_url()` would otherwise be required;
  - `esc_html()` and its i18n variants in a *quoted* attribute: they run
    `_wp_specialchars()` with `ENT_QUOTES`, so both quote characters are
    encoded (`wp_kses()` stays reportable: it passes markup through);
  - an escaper wrapping a hardcoded literal with no context-breaking
    character, e.g. `esc_html__( 'Open Date Picker' )` inside a script block.
  `esc_html()` in an *unquoted* attribute is still reported: it does not
  encode the space that ends an unquoted value.

Further precision changes from corpus adjudication of the new attribute rule:

- `wp.xss.wrong-context-escape` now judges a context held in a variable bound
  exactly once in the file, so a template assembled a line above its `echo` is
  read in both its `printf` and concat-then-echo forms. A name written more than
  once stays unjudged rather than guessed, and positional `%2$s` specifiers are
  mapped instead of ending the analysis.
- `json_encode()` / `wp_json_encode()` is treated as escaping for a JavaScript
  value position and nothing else: the rule reports it landing in HTML text, in a
  quoted attribute (whose quotes the JSON's own quotes end) or in an event
  handler, and credits `esc_attr( wp_json_encode( … ) )` and the pair inside a
  `<script>` block.
- A hook callback joined to a dispatcher only by a folded name prefix is analysed
  for its sinks but no longer replaces `apply_filters()`'s own escape-voiding
  semantics or its return, and a prefix matching more literal hooks than the
  fanout cap joins nothing: it is a plugin's namespace, not a hook family.
- `esc_sql()`'s quote check folds a non-literal query fragment (a `WHERE` clause
  built one call away) to its single string, so the escaped value after it is
  judged against the real quote state.
- A `$_FILES` sub-key (`tmp_name`, PHP's own path) merged from branches is
  followed back through the phi when every branch reaches a qualifying
  superglobal, clearing a false traversal report on `fopen()`.

### Changed

- The scan runs PHP's cycle collector itself, when the heap has grown by
  256MB, instead of every time ten thousand possible roots gather. The
  automatic collector walked the scan's live graphs over and over and freed
  almost nothing: on the client configuration's reference trees it took 58 of
  the first 85 seconds of parsing. Parsing jetpack went from 39 to 14 seconds.
  Findings are unchanged. `--debug-memory` shows the collector's time for each
  phase and round.
- Each round of the fixed point analyses functions grouped by file, with files
  ordered callees first, so a round needs each file at most once. The findings
  are unchanged. Over the 50-plugin corpus, 5 findings in 2 plugins show a
  different trace, because the trace kept for a stored value can depend on the
  order of analysis. `--jobs` already had the same effect. See
  KNOWN_LIMITATIONS.md.
- A REST route's `permission_callback` is credited by
  `wp.authz.object-id-from-request`. WordPress runs the route's callback only
  once the permission callback allows the request, so a callback whose
  permission callback allows only behind an entitling check, an object
  capability with the id or a site-wide one, is entitled, as is every function
  only entitled code calls. A role capability, `__return_true` or a missing
  callback still is not.
- `CapabilityGuard` follows a compound guard, `if ( ! current_user_can( … ) ||
  … )`, which php-cfg compiles to a branch on a phi and which was never
  credited, in a permission callback or in a handler. A permission callback
  returning a value `is_wp_error()` has just proved to be an error is refusing,
  not allowing.
- A REST route's `args` schema narrows its parameters in the route's callback,
  as `WP_REST_Request::sanitize_params()` does: a `sanitize_callback` in any
  callable form, or core's `rest_parse_request_arg()` when only a `type` is
  declared, with `enum`, the numeric types and string formats applied as core
  applies them.
- Fixed-point rounds after the first re-analyse only the functions that read
  something the previous round changed. Every read of a summary, property or
  scope entry is recorded as it happens, so a function whose reads did not
  move is known to produce what it produced before, rather than predicted to;
  within a round, a changed summary makes its readers later in the same slice
  dirty at once. Findings, traces and warnings are byte-identical to
  re-analysing everything, checked by `tools/compare-incremental.php` on all
  50 corpus plugins and a client scan with four reference trees, where the scan
  went from 339s to 155s.
- Peak memory is about a quarter lower on a scan with reference trees. A
  reference file's AST is released as soon as the file is indexed, since
  structural rules never run on reference trees, rather than after the call
  graphs are built, which is where the peak was. On a client scan with four
  reference plugins: 3,231MB to 2,445MB, identical findings.
- Building control flow graphs is about 3.5 times faster. php-cfg's simplifier
  re-walked the whole function for every trivial phi it removed, and was most
  of the parse time on real WordPress code. wp-taint now carries a copy with a
  linear replacement, which visits only the ops that use the variable. It also
  follows catch and finally edges that upstream's walk missed, so it never
  leaves a use pointing at a removed phi where upstream did not. Over the 50
  corpus plugins, 24,798 files: 23,976 identical graphs, 633 with fewer
  references to a removed phi and none with more, 6 differing only in phi
  operand order, and 183 that php-cfg's printer cannot print with either.
- `init` now asks with a checklist (Laravel Prompts) instead of typing
  comma-separated numbers: space to check the directories you wrote, and the
  rest become the reference set. The terminal guard is unchanged, so a
  non-interactive or CI run still writes the commented template rather than
  prompting.

## [0.1.0] - 2026-08-30

The first tagged release. Everything below shipped in it.

### Added

- Interprocedural taint analysis over SSA form, following values across
  functions, files, `include`/`require` and hook dispatches.
- 30 rules covering XSS, SQL injection, authorization, CSRF, path traversal,
  object injection, SSRF, open redirect, header and LDAP injection, and CSV
  formula injection.
- Taint as a set of kinds rather than a boolean, so an HTML escaper does not
  silence a database sink.
- Separate input and output obligations, so `esc_url_raw()` is credited for
  storing a URL and still reported for printing one.
- Escape-invalidation tracking: escaping that passes through a filter before
  reaching output is reported, including the several hundred core functions that
  run a filter and return the result.
- Context-sensitive escaping checks, down to the quote character around an
  attribute.
- Structural rules for bugs that are an absence rather than a value: missing
  capability checks, missing `permission_callback`, missing `sanitize_callback`
  on a registered setting, actionless nonces, bypassable nonce checks, guards
  that fall through.
- Closures, shortcodes, blocks and other entry points: what a closure captured
  through `use` is carried into its body; a shortcode callback's attributes are
  treated as post content and its return value as output; and a dynamic block's
  `render_callback` return is treated as output too, because WordPress prints
  it and there is no `echo` in the plugin to find.
- Remote HTTP response bodies (`wp_remote_retrieve_body()` and the header
  accessors) are sources: the endpoint may be one the plugin chose, the bytes
  that came back are not.
- `wp_add_inline_script()` is an output sink in a JavaScript context.
- Path sensitivity through php-cfg assertions, plus dominance-based guard
  detection for validators php-cfg does not assert on.
- `scan`, `explain`, `registry:dump` and `dump-cfg` commands.
- Console, JSON and SARIF output.
- Baselines and inline `wp-taint-ignore-next-line` suppressions.
- `wp-taint.toml` project config with separate `paths`, `reference` and
  `bootstrap` lists, the last for files whose `define()`s the scan should
  know, such as `ABSPATH`.
- `get_template_directory()` and the constant chains themes hang off it fold to
  the theme a file is in, so a theme's own `require_once THEME_INC . '…'`
  connects.
- Path-helper returns fold at call sites: a function returning
  `__DIR__ . "/views/$view"` called with a literal resolves the include.
- `--include-path` for trees analysed for symbols but never reported on.
- Output that nothing vouches for is reported by default, at `low`, seeded only
  at entry points: a function nothing in the scan calls.
  `--no-unknown-provenance` asks the narrower "can I trace this to something
  dangerous" instead.
- `--stored-taint-writes` to report unsanitised data written into options and
  meta.
- Parallel analysis with `--jobs`, producing identical findings at any job
  count.
- A TOML catalogue of sources, sinks, sanitizers and propagators, with unknown
  keys as hard errors. Two parts are generated from WordPress itself and checked
  for drift in CI.
- Progress reporting on stderr for scans over 250 ms.

### Evidence

Five independent measurements, all checked in CI:

- 252 first-party fixtures, 127 of them labelled safe. A single false positive
  in the safe half fails the build.
- A 50-plugin corpus from WordPress.org: 21,148 files, 4.1 million lines. Eight
  plugins are pinned by version and their counts are asserted.
- The WordPress plugin team's intentionally vulnerable plugin: 12 of 12
  documented issues found.
- 47 real CVEs, scanned both sides of the fix.
- Two third-party fixture suites written elsewhere, scored by their own scorers:
  precision 0.98, recall 0.94, F1 0.96 by default; precision 1.00, recall 0.77
  with `--no-unknown-provenance`. The second suite, scored by its own
  comparator, is at 7 missing of 36 scenarios.

### Known limitations

Documented in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). A false positive
rate under 10% on the corpus is being demonstrated one rule at a time under
`docs/triage/`. The first slice, `wp.authz.rest-public-write`, was 29 findings
and 0 false positives; the rest are outstanding.

[Unreleased]: https://github.com/darylldoyle/wp-taint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/darylldoyle/wp-taint/releases/tag/v0.1.0
