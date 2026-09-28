# Changelog

All notable changes to wp-taint are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A comparison with a literal is a guard. `===` and `!==` with a literal or a
  constant hold the value to it. A loose `==`, `!=` and a `switch` case count
  only against a string that is not numeric, which a loose comparison cannot
  stretch. `empty()` counts too. Both sides of `&&` and `||` are read both
  ways, so `'grid' === $mode || 'list' === $mode` is a two-value allowlist.
- A `self_quoted` key for `[[sanitizers]]`: the entry returns one quoted
  literal or identifier of its own, safe where the query writes it bare.

- `wp.sqli.identifier-choice`, at medium: a request value names a column or
  table inside backticks. Escaping the backticks keeps it one identifier, and
  the request still chooses which. A check against a fixed list settles it.

- `registries/php-generated.toml`, written by `tools/generate-php-catalogue.php`
  from reflection: each of PHP's own functions declared to return something
  that can hold text, with the parameters declared to hold text. The engine
  reads an `[[internal]]` entry only for a call nothing else models.
- An `alphabet` key for `[[sanitizers]]`. `alphabet = "A-Za-z0-9+/="` says what
  characters the output can hold, and the kinds it clears are worked out from
  them by the same proof a guard gets.
- `getallheaders()` and `apache_request_headers()` are request sources.
  `curl_exec()` and `curl_multi_getcontent()` are stored sources, like
  `wp_remote_retrieve_body()`.

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

- An escaped SQL value lost its SQL kind through a helper's return.
  `$q = acme_id( esc_sql( $_GET['x'] ) )` used unquoted was not reported, and
  neither was a self-quoted value returned into quotes. A helper's summary is
  built from `sql`, and the escaped kinds were not in it. A helper now hands a
  residual back with its `sql`, and one that may undo the escaping hands it
  back as `sql`.

- A guard credited a value written after it under the same name. `if ( empty(
  $x ) ) { $x = $_POST['y']; echo $x; }` and a digit check followed by `$id =
  $id . $_GET['s']` went unreported. A guard now covers the value it tested,
  and a join carries the proof only from the operand that was tested.
- UpdraftPlus's `escape_table_name()` cleared `sql` wherever its result went.
  It returns one quoted identifier, so a result placed inside quotes is now
  reported.
- A `str_replace()` identifier escaper read its search and replacement only
  when they were written as literals. Yoast's ORM keeps the backtick in a
  variable, so its quoted column names were reported as injections.

- An escaped SQL value's quotes were read only at the sink. A clause built as
  `"AND name LIKE '%" . esc_sql( $s ) . "%' "` and joined into a query later
  read as unquoted, a false critical in WooCommerce's API key list. A helper
  that escaped its argument lost the fact on the way back, so its return used
  unquoted was clean. A caller's escaped argument used unquoted one call down
  was missed. Each concatenation now decides what its own quotes hold: an
  escaped value inside quotes it opens and closes becomes `sql_self_quoted`,
  safe bare and unsafe inside more quotes. Literal `sprintf()` formats and
  `implode()` glue are read the same way. A helper hands its caller the
  residual it made, and a callee records whether its query puts the argument
  bare or inside quotes.
- An identifier escaped for backticks read as raw SQL. `str_replace( '`',
  '``', $col )` into `` "SELECT `$col` FROM t" `` was reported, and the same
  value placed bare was reported only for being raw. Doubling or removing every
  backtick now makes a value safe inside backticks only, with its own finding
  when it lands outside them. A `str_replace()` that escapes the backslash and
  then both quotes is credited like `esc_sql()`.
- An escaped SQL value stayed escaped through any function. `stripslashes(
  esc_sql( $v ) )`, `rawurldecode()` of it and `trim()` with a mask can each undo
  the escaping. Only the functions the catalogue marks `keeps_residuals` now
  keep it; after any other, the value is `sql` again.
- A document or container loaded from the request came back clean.
  `$dom->loadHTML( $_POST['html'] ); echo $dom->saveHTML();` was missed, and so
  were `new ArrayObject( $_POST )`, an `SplQueue` of request values,
  `simplexml_load_string( $_POST['xml'] )->title` and an exception's message.
  The DOM, SimpleXML, the SPL containers and exceptions now hold what they are
  given: a method that returns text returns its arguments' and its object's,
  and one that keeps its arguments puts them into the object. The methods are
  generated from reflection, and which ones keep their arguments is a reviewed
  list in the generator.
- `filter_var()`, `filter_var_array()`, `filter_input()` and
  `filter_input_array()` were unlisted, so they returned clean whatever the
  filter. They now read the filter constant. `FILTER_VALIDATE_INT` and the
  other number filters clear every payload, an address or number-sanitising
  filter clears what its characters cannot carry, and the special-characters
  filters clear HTML. `FILTER_DEFAULT`, `FILTER_VALIDATE_EMAIL`,
  `FILTER_VALIDATE_URL` and any filter not written as a constant pass the value
  through. The `filter_input()` pair are request sources.
- A `preg_replace()` pattern's taint went into the result, though the pattern
  only chooses what is replaced. WooCommerce trims every price with a pattern
  built from its stored decimal separator, so each formatted price read as
  stored HTML once `preg_quote()` carried the separator. The pattern argument
  no longer counts.
- A PHP function the catalogue did not list returned clean, whatever it
  returned. `explode( ',', $_GET['ids'] )` was clean, and so were `array_pop()`,
  `strstr()`, `dirname()`, `max()` and 300 more that the 50-plugin corpus calls
  25,000 times. Each now returns the text of its arguments when PHP declares it
  to return something that can hold text. An argument declared as a number or a
  flag carries nothing. Hashes, class and type names, settings and output
  alphabets are modelled by hand, and so are `chr()` and `mb_chr()`, whose
  number is the character.
- A propagator dropped an array element written under a literal key.
  `implode( ',', array( 'k' => $_GET['v'] ) )` returned clean, so echoing it
  was missed. An element under a literal key now travels with the others. A
  propagator whose result keeps its input's keys, `array_filter()`,
  `array_merge()`, `array_slice()`, `shortcode_atts()`, the unslashers and the
  `apply_filters()` family, keeps it under its key, so a stored `'value'` does
  not taint the `'id'` read beside it. The catalogue says which with
  `keeps_keys = true`.
- A trace could stop before its source, or name the wrong one. The walk
  followed the first predecessor that held the kind in its own slot. So it
  missed a value held in an array's elements, and in a loop it stopped at the
  value from the last time round. It now tries each predecessor that holds the
  kind anywhere, and backs out of any that lead nowhere. When no predecessor
  holds the kind, the walk used to go on through the first one anyway, so a
  summary that returns stored `html` whatever its argument was traced back to
  the request value passed in. The trace now starts there. A kind made from
  another, `sql_unquoted` from `sql`, is still followed upstream through the
  kind it was made from.
- A `foreach` key took the taint of the collection's elements. After
  `$rows[ $i ] = $_GET['x']`, the `$k` in `foreach ( $rows as $k => $v )` was
  reported as request data. It now takes the collection's own taint only.
- A less severe finding could hide a more severe one on the same line. The
  rule precedence let `wp.xss.escape-voided`, a medium, replace
  `wp.xss.unescaped-output`, a high, whenever both reported one echo. On one
  client tree that hid 362 highs. A function returned a value that was raw on
  one path and voided on another, and each echo of it showed only the medium.
  The specific finding now wins outright only when it is at least as severe.
  Two findings whose traces start at one place tell one story: the specific
  finding stays and takes the higher severity, with a trace step saying why.
  Two that start apart are two flows, and both are reported.
- A guard cleared every kind when it proved one. `! preg_match( '/[<>]/', $v )`
  cleared SQL and shell as well as HTML, and a character check such as
  `/^[a-z0-9 ]+$/` or a strip such as `preg_replace( '/[^a-zA-Z0-9 ]/', … )`
  cleared SQL outside quotes, where `1 OR 1` needs only letters and a space.
  Guards and strips now share one proof, `CharacterProof`: each kind clears
  when the value cannot hold a character that carries syntax for it, and SQL
  clears inside quotes only when the value can hold whitespace, a comment
  opener, a parenthesis, a dash or an operator. A character check no longer
  settles a name, so `ctype_alpha()` before `update_option()` is still an
  arbitrary option write. A pattern with the `m` or `x` modifier, which the
  guard read as if it had none, now proves nothing.
- The catalogue credited escapers for more than they do, or missed them:
  - `like_escape()` counted as a quote escaper. It escapes the LIKE wildcards
    and the backslash, never a quote, so a LIKE pattern built from it and
    quoted read as safe. It and `wpdb::esc_like()` now pass their argument
    through.
  - `addslashes()`, `mysqli_real_escape_string()`, `wpdb::_escape()` and the
    deprecated `wpdb::escape()` were unlisted. An unlisted function returns
    clean, so they cleared every kind in every context. They are now quote
    escapers like `esc_sql()`: safe inside quotes, reported outside them.
  - `_wp_specialchars()` was unlisted. It now clears HTML in text only. By
    default it encodes no quote, so an attribute built from it is reported.
- A value one of whose branches could not be followed was read as the
  branches that could. `$c ? "'" : $x` folded to a quote, so an `esc_sql()`
  value after it read as quoted even when `$x` is not a quote. A join now
  folds only when every branch does, for the query shape rule and for
  constants. Hook, callback, class and include resolution still use the
  branches that fold, through a separate `ValueResolver::knownStrings()`,
  because the callees it can name are better than none.
- A call's arguments went to the parameter at the same position as written,
  and several kinds of call do not work that way. Each lost a flow:
  - `f( ...$args )` handed `$args` to the first parameter and nothing to the
    rest.
  - `call_user_func_array( $cb, $args )`, `do_action_ref_array()` and
    `apply_filters_ref_array()` did the same.
  - `f( label: $x, field: $y )` handed `$x` to whichever parameter came first.
  - `function f( $a, ...$rest )` never received a third argument.
  - `array_map( $cb, $a, $b )` handed `$cb` nothing from `$b`.
  - `array_walk()` never handed over its third argument, and
    `array_reduce()` gave its callback's carry the items instead of the
    initial value.

  An unpacked array now goes to every parameter from its position on. A
  literal array handed to `call_user_func_array()` goes to the parameters its
  keys name, and a named argument to the parameter of that name. A variadic
  parameter collects every argument from its position. A dispatcher's
  catalogue entry can now list where each of its callback's parameters gets
  its value, and `array_filter()`, `array_walk()`, `array_reduce()` and the
  sorts do. An `array_reduce()` carry receives the initial value and the
  items.
- A property read on a variable that php-cfg joins from several places lost
  the variable's class. `if ( $on && ( $class = $r->getClosureCalledClass() ) )`
  joins `$class` from before the condition with the one assigned in it, so
  `$class->name` fell to the slot every unresolved `->name` shares. That let
  Elementor's request-filled post type labels reach bundled Twig's `eval()`.
  A property's owner is now read through a join when every way in names the
  same class. A literal, `null`, an array, or a local nothing else can set
  carries no object and does not count against it. A local counts as unset
  only in a function that never passes it to a call, binds it by reference,
  declares it global or static, or uses `include`, `eval`, `extract()` or a
  variable variable.
- A function that returned an array lost the taint of its elements.
  `$a['title'] = $_GET['title']; return $a;` was clean to every caller, and so
  was an element written under a computed key. A summary now records what each
  parameter puts into the returned array's elements, and what the body puts
  there itself, by key. A caller reads them off the call result as it reads a
  local array. A trace through such an element now starts at the write into
  it, not at the read.
- A callee received every element of an array argument, including elements it
  never reads. WooCommerce's settings page hands each field's array, with the
  stored option under `value`, to a helper that reads only `desc` and
  `desc_tip`. The option came back out as the field's description. A summary
  now lists the literal keys a function reads each parameter through, when it
  reads the parameter no other way, and a caller hands such a callee only
  those elements. The array's own taint and its computed-key elements still go
  in. A call written with `...$args`, and a callback run by `array_map()`,
  `call_user_func_array()` or their relatives, still hands on the whole
  argument, because the array there is not one parameter's value.
- A property read on a value that one of PHP's own methods returned shared a
  slot with every write to a property of that name the scan could not place.
  `$r->getClosureCalledClass()->name` read whatever any `$labels->name = …`
  had written, so request data written into a post type's labels reached
  Twig's template compiler. PHP's reflection says what its own functions and
  methods return, and a property read or write on such a value now uses that
  class. Only a concrete class of PHP's own that nothing in the scan extends
  counts. A method call on the value is still followed as a dynamic call.
- A guard only suppressed a finding when the sink's argument was the guarded
  variable itself. `if ( ctype_digit( $id ) ) { $wpdb->query( 'DELETE … ' .
  $id ); }` was SQL injection, because the sink's argument is the
  concatenation. So was a check on an element, `in_array( $params['orderby'],
  … )`, and a check on the right-hand side of `isset( $x ) && …`, which php-cfg
  lowers to a join the guard could not read. A guarded value now keeps only an
  object id wherever it is assigned, concatenated or passed. Elements under a
  literal key and normalised copies are guarded by name, and both sides of
  `&&` and `||` are read.
- A guard was credited when only one way into the code after it had passed
  the check. `if ( ! ctype_digit( $x ) ) { $y = 1; } echo $x;` reported
  nothing, though the branch that failed the check falls into the echo. Every
  way in now has to pass the check, end first by returning, throwing, exiting
  or calling `wp_die()` or `wp_send_json()` and its variants, or replace the
  value with a literal.
- A REST parameter that the route's permission callback admits only from a
  fixed list was read as arbitrary request data. Rank Math's schema routes let
  a request through only when `objectType` is `post`, `term` or `user`, and
  the callback builds a table name from it. That read as SQL injection. When
  every return that lets a request through is behind a strict allowlist check
  on the parameter, directly or in a helper handed the same request, the
  callback now reads it as one of a fixed list: no payload, though it can
  still name another object.
- UpdraftPlus's table-name escaper was read as passing SQL taint through.
  `UpdraftPlus_Database_Utility::escape_table_name()` doubles every backtick and
  wraps the name in backticks, MySQL's rule for a quoted identifier, and the
  result carries its own quotes. The catalogue now lists it as clearing SQL
  taint. Two critical findings in UpdraftPlus go, both queries on a table named
  through it.
- A callee that cleared a kind on the way to a property, a closure's capture,
  or a file it included still passed that kind on. The caller published its
  whole argument there. `$this->v = esc_html( $x )` stored HTML taint when the
  caller passed request data, and a template included after
  `$label = esc_html( $x )` reported unescaped output. The summary now records
  the kinds that reach each place, and the caller publishes only those. A
  request id that a callee passes through `absint()`, and uses to load a record
  that it then hands to an included file, no longer makes that file's copy of
  the record look like request data.
- The authorization rules credited a check inside a hook callback. Walking the
  call graph from an AJAX or `admin_post_` handler, a REST permission callback,
  or a helper guarding an object operation, the walk followed hook dispatches
  into their callbacks. A public AJAX endpoint that read a plugin option was
  credited with the `current_user_can()` inside a filter on that option, four
  calls down. That check shapes the option's value and guards nothing in the
  handler. The scan also cannot know which callbacks are on a hook when it
  fires, the reason a filter callback is not credited as a sanitiser either.
  The walk now follows direct calls only. Hook callbacks still have a caller,
  so they are not treated as entry points.
- Callbacks on Gravity Forms hooks received nothing from the dispatch. Gravity
  Forms fires its hooks through `gf_do_action()` and `gf_apply_filters()`,
  with the hook name and its modifiers in an array:
  `gf_do_action( array( 'gform_after_submission', $form_id ), $entry, $form )`
  fires `gform_after_submission` and `gform_after_submission_{$form_id}`. The
  catalogue now models both as dispatchers, with a new `hook_modifiers` flag
  that reads the array. A modifier held in a variable joins by prefix. The
  older form, `gf_apply_filters( 'gform_media_upload_path', $form_id, $dir )`,
  is read too, with the value as the third argument. A callback on
  `gform_after_submission` now sees the submitted entry, which holds what the
  visitor typed.

  A line that echoes a form, such as `echo gravity_form( $id )` with a tainted
  id, moves from high unescaped output to medium escape-voided.
  `gf_apply_filters()` now voids escaping the way `apply_filters()` does, so
  the line gets both findings, and the precedence rule reports only the
  escape-voided one. The unescaped-output finding is still raised underneath.
  See "One output line reports once" in KNOWN_LIMITATIONS.md.
- A file included from a function, or a template loaded with
  `get_template_part()`, was reported as receiving tainted input whenever the
  function had a parameter, even when every caller passed a literal. The
  summary's probe runs, which seed a parameter with every kind of taint to see
  where it goes, published that seed into the scope the included file sees.
  `function acme_render( $data ) { include 'tpl.php'; }` called only as
  `acme_render( 'hello' )` was a high XSS finding in `tpl.php` with all sixteen
  kinds. The probe now records where its seed would have gone, and each caller
  publishes what it actually passed, as property writes and closure captures
  already did. A caller passing request data is still reported, with its
  source at the start of the trace and only the kinds it carries.
- A function with thousands of blocks could take gigabytes of memory for its
  dominators alone. The algorithm starts with every block dominating every
  block, and held that as object sets, so a function of n blocks began with n²
  entries. A generated theme file in one site's reference trees had a function
  of 7,910 blocks: about 63 million entries, over 4GB, which ran the scan out
  of memory at an 8GB limit and at a 12GB one. The sets are now bit words, and
  the callers read them without building objects. Every dominator set across
  422,874 functions in 168 reference trees matches the old algorithm's, and the
  three largest functions take 0.9 seconds instead of 11.
- The out-of-memory message always suggested `WP_TAINT_MEMORY_LIMIT=6G`, so a
  scan that died at 12G was told to try half as much. It now suggests double
  the limit the scan had, or a lower `--memory-budget`, which needs less memory
  and takes longer.
- `format`, `fail_on`, `min_severity` and `jobs` under `[scan.options]` in
  `wp-taint.toml` were ignored. Each matching command-line option had a
  built-in default, so it always counted as given and always won. A config
  asking for `format = "json"` produced console output, and `fail_on =
  "critical"` still failed the build at `high`. The config file's values now
  apply, and an option given on the command line still overrides them.
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

- A file the graph cache lets go of is taken apart, so it frees at once
  instead of waiting for the cycle collector. A php-cfg graph is a web of
  cycles, and under a memory budget every file the cache does not hold becomes
  one more of them to collect. Files are retired when dropped and taken apart
  only between units of work, where nothing reads them again: the next
  function of a sweep, group of a round, function of the findings pass. On a
  site with 17 reference trees at the default budget, the peak heap fell from
  6.17GB to 5.19GB and collection from about 64 seconds to 14, for 3% more
  time; findings are byte-identical. `--dump-taint-graph`, which keeps every
  analysis's state, turns it off.
- The object-authorization check settles whether each block is guarded once
  per function, instead of searching again on every question. "Does an
  entitling check dominate this block" recursed through every phi's inputs and
  kept no answers, so a 3,000-line import routine in a commercial plugin
  asked it 185,000 times in one analysis: 38 of that analysis's 47
  seconds, ten analyses a round. The question is a set of "this holds if all
  of these hold" rules with no negation, and a counting pass now computes
  their least fixed point, which is exactly what the recursive search
  answered. A scan running both over the 50-plugin corpus compared 9,882
  answers and found no difference.
- Setup walks every function four times, not six. Hook registrations, include
  sites and REST routes need only the constant table, and they are now
  collected in one sweep. Under a memory budget every sweep rebuilds every
  file the cache does not hold, so this is two fewer rebuilds of each. The
  call graph needs the finished hook graph and keeps its own sweep.
- The hook graph remembers its answers. The analysis asks which callbacks a
  hook runs at every dispatch, on every pass of every analysis, and each
  answer sorted every matching registration again; a computed hook name such
  as `"save_post_{$type}"` also scanned every hook in the scan. The graph does
  not change once built, and any change empties the answers.
- A call on a receiver of unknown class names every method of that name in
  the scan. That list is now built once per name instead of once per call.
- With `--jobs`, the findings pass gives each worker a contiguous run of
  functions instead of every Nth one. Functions are listed file by file, so
  striping made every worker rebuild every file the cache does not hold. The
  runs also put warnings in the order one process gives them.
- A function declared in several files, such as a library several plugins
  each bundle, no longer rebuilds every copy's file for every method. The
  fixed point fetched each body twice per round, once per pass, and kept one
  rebuilt file at a time, so a class of m methods copied into k files the
  cache does not hold cost 2km rebuilds a round. Each body is now fetched once
  a round, and an eighth of `--memory-budget` is a pool that keeps every file
  rebuilt while one file's functions are analysed. On a site with 168
  reference trees, three bundled copies of one PDF library had cost 55 to 94 seconds per
  method, for hundreds of methods. Findings are unchanged; `--debug-memory`
  reports the pool's size.
- The scan runs PHP's cycle collector itself, when the heap has grown by
  1GB, instead of every time ten thousand possible roots gather. The
  automatic collector walked the scan's live graphs over and over and freed
  almost nothing: on one large site's reference trees it took 58 of
  the first 85 seconds of parsing. Parsing jetpack went from 39 to 14 seconds.
  Findings are unchanged. `--debug-memory` shows the collector's time for each
  phase and round.
- Each function's block dominators are computed once per analysis pair
  instead of four times. The guard and capability checks both asked for them,
  in both the summary pass and the property pass, and on a 40-tree scan that
  was an eighth of the fixed point's time. Together with the 1GB collector
  step, that scan went from about 1,100 to about 930 seconds with the same
  findings.
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
  50 corpus plugins and a production scan with four reference trees, where the scan
  went from 339s to 155s.
- Peak memory is about a quarter lower on a scan with reference trees. A
  reference file's AST is released as soon as the file is indexed, since
  structural rules never run on reference trees, rather than after the call
  graphs are built, which is where the peak was. On a production scan with four
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
