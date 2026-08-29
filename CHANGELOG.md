# Changelog

All notable changes to wp-taint are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No release has been tagged yet. Everything below is in `main` and is what 0.1.0
will contain.

### Added

- Interprocedural taint analysis over SSA form, following values across
  functions, files, `include`/`require` and hook dispatches.
- 29 rules covering XSS, SQL injection, authorization, CSRF, path traversal,
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
  capability checks, missing `permission_callback`, actionless nonces,
  bypassable nonce checks, guards that fall through.
- Path sensitivity through php-cfg assertions, plus dominance-based guard
  detection for validators php-cfg does not assert on.
- `scan`, `explain`, `registry:dump` and `dump-cfg` commands.
- Console, JSON and SARIF output.
- Baselines and inline `wp-taint-ignore-next-line` suppressions.
- `wp-taint.toml` project config with separate `paths` and `reference` lists.
- `--include-path` for trees analysed for symbols but never reported on.
- `--unknown-provenance` to ask "is this proven safe" instead of "can I trace
  this to something dangerous", seeded only at entry points.
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

- 226 first-party fixtures, 115 of them labelled safe. A single false positive
  in the safe half fails the build.
- A 50-plugin corpus from WordPress.org: 21,148 files, 4.1 million lines. Eight
  plugins are pinned by version and their counts are asserted.
- The WordPress plugin team's intentionally vulnerable plugin: 12 of 12
  documented issues found.
- 47 real CVEs, scanned both sides of the fix.
- Two third-party fixture suites written elsewhere, scored by their own scorers:
  precision 0.98, recall 0.84, F1 0.91 with `--unknown-provenance`.

### Known limitations

Documented in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). A false positive
rate under 10% on the corpus has not been demonstrated; that gate needs a
finding-by-finding triage and remains outstanding.

[Unreleased]: https://github.com/darylldoyle/wp-taint/commits/main
