# Changelog

All notable changes to wp-taint are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Object-level authorization detection, the largest previously-silent class in
  the authorization column.
  - `wp.authz.object-id-from-request` reports a request-chosen post, comment,
    term or user id reaching an object operation (`wp_delete_post()`,
    `update_user_meta()`, `wp_set_password()` and their relatives) when no
    check dominating the sink entitles the caller to that object. This is the
    classic WordPress IDOR (CWE-639): the check is present and correctly named,
    but scoped to a role rather than the row. A new `object_id` taint kind
    carries the id and — unlike every payload kind — survives `absint()`,
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
- Inherited-method call resolution. Method lookup was flat — `Class::method`
  exactly as written — so a method inherited from a parent or brought in by a
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
  conflict resolution is not modelled, and a parent outside the scan still
  ends the walk unresolved rather than guessed at.

### Fixed

Four precision fixes from adjudicating every finding of a Gravity Forms scan
(92 findings: 0 exploitable, 75 correct catches, 17 false positives — the fixes
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
  - `absint()`/`intval()` anywhere — an integer carries no breakout, including
    in a URL attribute where `esc_url()` would otherwise be required;
  - `esc_html()` and its i18n variants in a *quoted* attribute — they run
    `_wp_specialchars()` with `ENT_QUOTES`, so both quote characters are
    encoded (`wp_kses()` stays reportable: it passes markup through);
  - an escaper wrapping a hardcoded literal with no context-breaking
    character, e.g. `esc_html__( 'Open Date Picker' )` inside a script block.
  `esc_html()` in an *unquoted* attribute is still reported: it does not
  encode the space that ends an unquoted value.

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
  `bootstrap` lists — the last for files whose `define()`s the scan should
  know, such as `ABSPATH`.
- `get_template_directory()` and the constant chains themes hang off it fold to
  the theme a file is in, so a theme's own `require_once THEME_INC . '…'`
  connects.
- Path-helper returns fold at call sites: a function returning
  `__DIR__ . "/views/$view"` called with a literal resolves the include.
- `--include-path` for trees analysed for symbols but never reported on.
- Output that nothing vouches for is reported by default, at `low`, seeded only
  at entry points — a function nothing in the scan calls.
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
