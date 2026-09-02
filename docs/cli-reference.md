# CLI reference

Every command, option, config key and exit code.

```
wp-taint <command> [options] [arguments]
```

| Command | Purpose |
|---------|---------|
| `init` | Detect a WordPress project and write a `wp-taint.toml` |
| `scan` | Find bugs. The default command. |
| `explain` | Show the taint state at one line, and why |
| `registry:dump` | Print the fully resolved catalogue |
| `dump-cfg` | Print the SSA control flow graph for a file |

## init

```
wp-taint init [options] [<root>]
```

`root` is the `wp-content` directory, or a project holding one. Defaults to the
current directory. Detects the themes and plugins, then writes a `wp-taint.toml`.

| Option | Effect |
|--------|--------|
| `--all` | Treat every detected directory as first-party. No prompt. |
| `--force` | Overwrite an existing `wp-taint.toml` |

What it writes depends on how it runs:

| How it runs | Result |
|-------------|--------|
| Interactive terminal | A checklist of the detected directories: the ones you check become `[scan] paths`, the rest become `reference` |
| `--all` | Every detected directory becomes a scan path |
| Non-interactive (CI, piped) | A template with every directory commented out |

The template path is deliberate: a scan in CI writes the template rather than
hanging on a prompt that has no terminal to answer it.

## scan

```
wp-taint scan [options] [--] [<paths>...]
```

`paths` are the files and directories to report on. Omit them to use the
`[scan] paths` in `wp-taint.toml`.

### Choosing what is analysed

| Option | Default | Effect |
|--------|---------|--------|
| `--include-path=PATH` | none | Analyse this tree for symbols, never report on it. Repeatable. |
| `--bootstrap=FILE` | none | A file whose `define()`s the scan should know, e.g. `ABSPATH`. Repeatable. |
| `--exclude=GLOB` | none | Skip paths matching this glob. Repeatable. |
| `--config=FILE` | `./wp-taint.toml` | Project config file |
| `--registry=NAME` | `wordpress` | Registry name, or a path to a TOML file |

### Choosing what is reported

| Option | Default | Effect |
|--------|---------|--------|
| `--min-severity=LEVEL` | `low` | Hide findings below this level |
| `--fail-on=LEVEL` | `high` | Exit 1 at or above this level, or `never` |
| `--baseline=FILE` | none | Suppress findings listed in this file |
| `--generate-baseline[=FILE]` | off | Write current findings to a baseline and exit |
| `--no-structural-rules` | off | Run taint analysis only |
| `--no-phpcs-suppressions` | off | Report at full severity even on a line the author marked reviewed with a matching `phpcs:ignore` |

Severity levels are `notice`, `low`, `medium`, `high` and `critical`.

### PHPCS-acknowledged findings

A line carrying a `phpcs:ignore` that names the sniff a rule maps to is the
author saying "I looked at this line, and here is why". So the finding is not
silenced, it is reported as a `notice` (below `low`, never fails a build), with
the sniff and the author's reason in its trace.

```php
echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from esc_html'd parts
```

Only a line-specific ignore that names the matching sniff counts. A bare
`phpcs:ignore`, a sniff for a different rule, and `phpcs:disable`/`enable`
ranges are ignored: a block disable is how bad code gets hidden wholesale,
which is exactly where the analyser should keep looking. `--no-phpcs-suppressions`
turns the whole behaviour off, for auditing code whose author's judgement you
do not share.

### Changing the analysis

| Option | Default | Effect |
|--------|---------|--------|
| `--stored-taint-writes` | off | Report untrusted data written **into** options and meta |
| `--no-unknown-provenance` | off | Report only traced flows, not output nothing vouches for |
| `--no-stored-taint` | off | Stop treating options and post meta as tainted |
| `--no-interprocedural` | off | Do not follow taint across function boundaries |
| `--no-follow-includes` | off | Do not join scopes across `include` and `require` |
| `--dynamic-calls=MODE` | `propagate` | `clean`, `propagate` or `tainted` for an unresolvable callee |

Output nothing vouches for is reported by default, at `low`, which is below the
default `--fail-on` and so cannot fail a build on its own. WordPress's standard
is escape on output wherever the value came from. A reader who knows the value
is safe dismisses a `low` in a second; a reader who is never shown it cannot. `--no-unknown-provenance` asks the narrower question, "can
I trace this to something dangerous". See [How it works](how-it-works.md).

### Output

| Option | Default | Effect |
|--------|---------|--------|
| `--format=FORMAT` | `console` | `console`, `json` or `sarif` |
| `-o, --output=FILE` | stdout | Write the report to a file |
| `--verbose` | off | Print every trace step, not just source and sink |
| `--trace-full` | off | Never collapse the middle of a long trace |
| `--parse-report` | off | List files that failed to parse, then exit |
| `--dump-taint-graph=FILE` | none | Write a GraphViz dot file of the taint graph |

Console output is lossy by design. Use `--format=json` to hand results to
another tool or an agent: it carries the full trace and is self-describing.

### Performance

| Option | Default | Effect |
|--------|---------|--------|
| `-j, --jobs=N` | `1` | Worker processes. Needs `ext-pcntl`. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean, or nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Execution error, including any file that failed to parse |

## explain

```
wp-taint explain <file.php:LINE> [options]
```

Prints the taint at that line and the reasoning that produced it, including
where the engine gave up. Use it on a finding you doubt, and on a line you
expected to be flagged and was not.

| Option | Default | Effect |
|--------|---------|--------|
| `--scope=DIR` | none | Directory to analyse for cross-file flows |
| `--kind=KIND` | all | Ask about one taint kind |
| `--registry=NAME` | `wordpress` | Registry name or path |
| `--no-follow-includes` | off | Do not join scopes across `include` and `require` |
| `--dynamic-calls=MODE` | `propagate` | `clean`, `propagate` or `tainted` for an unresolvable callee |

> **Important**
> `--scope` is not optional in practice. Without it the file is analysed alone,
> so anything arriving through an include or a hook reports clean.

## registry:dump

```
wp-taint registry:dump [--registry=NAME] [--config=FILE] [--format=text|json]
```

Prints every source, sink, sanitizer, propagator and rule after all registries
are merged. Use it to confirm a function is modelled the way you think.
`--format` defaults to `text`.

## dump-cfg

```
wp-taint dump-cfg <file> [--format=text|dot] [--show-lowering]
```

Prints the SSA control flow graph for one file, a debugging aid for the engine
itself rather than part of a normal scan. `--show-lowering` lists the constructs
rewritten before the graph is built.

## Project config

`wp-taint.toml`, found by walking up from the working directory.

```toml
[scan]
paths     = ["themes/client-theme", "plugins/client-shared"]
reference = ["plugins/some-dependency"]
bootstrap = ["wp-taint-bootstrap.php"]
exclude   = ["*/vendor/*", "*/node_modules/*"]

[scan.options]
jobs                = 4
fail_on             = "high"
min_severity        = "low"
format              = "console"
baseline            = "wp-taint-baseline.json"
stored_taint_writes = false
```

| Key | Equivalent flag |
|-----|-----------------|
| `paths` | positional arguments |
| `reference` | `--include-path` |
| `bootstrap` | `--bootstrap` |
| `exclude` | `--exclude` |
| `options.jobs` | `--jobs` |
| `options.fail_on` | `--fail-on` |
| `options.min_severity` | `--min-severity` |
| `options.format` | `--format` |
| `options.baseline` | `--baseline` |
| `options.stored_taint_writes` | `--stored-taint-writes` |

Unknown keys are a hard error rather than a silent typo. Anything on the command
line wins, and paths given as arguments replace the configured ones.

## Suppressing a finding

```php
// wp-taint-ignore-next-line wp.xss.unescaped-output -- output is admin-only, reviewed 2026-08
echo $header;
```

`//`, `#` and `/*` all work. The rule id accepts `*` as a wildcard. The reason
after `--` is required.

## Rules

33 rules. The id is stable and is what you suppress or filter on.

### Output

| Rule | Reports |
|------|---------|
| `wp.xss.unescaped-output` | Untrusted input reaches output unescaped |
| `wp.xss.unescaped-attribute` | Sanitised input (tags stripped) reaches a quoted attribute; its quotes can end the attribute |
| `wp.xss.escape-voided` | Escaped, then passed through a filter that can replace it |
| `wp.xss.wrong-context-escape` | Escaped for the wrong context, e.g. `esc_html` in an `href` |
| `wp.output.unescaped-unknown` | Output with nothing vouching for it |
| `wp.output.csv-injection` | Exported value can be a spreadsheet formula |

### Database

| Rule | Reports |
|------|---------|
| `wp.sqli.wpdb-query` | Untrusted input reaches a `$wpdb` query |
| `wp.sqli.unprepared-query` | A variable interpolated into a query, origin unaccounted for |
| `wp.sqli.prepare-non-literal` | `prepare()` with a format string built from a variable |

### Authorization and CSRF

| Rule | Reports |
|------|---------|
| `wp.authz.ajax-missing-check` | AJAX handler with no capability or nonce check |
| `wp.authz.admin-post-missing-check` | `admin-post.php` handler with no check |
| `wp.authz.rest-missing-permission-callback` | REST route with no `permission_callback` |
| `wp.authz.rest-permission-callback-no-check` | A `permission_callback` that checks nothing |
| `wp.authz.rest-public-write` | A public REST route that writes |
| `wp.authz.arbitrary-option-write` | The option name comes from the request |
| `wp.authz.object-id-from-request` | A request-chosen post, comment, term or user id reaches an object operation with no object-scoped capability check |
| `wp.authz.meta-cap-without-object` | A meta capability (`edit_post`, `delete_user`) checked with no object id |
| `wp.authz.guard-without-exit` | A failed check that falls through |
| `wp.csrf.nonce-without-action` | A nonce with no action, which any valid nonce satisfies |
| `wp.csrf.bypassable-nonce-check` | A nonce check an attacker skips by omitting the nonce |

### Code and file execution

| Rule | Reports |
|------|---------|
| `wp.rce.eval` | Untrusted input reaches `eval()` |
| `wp.rce.shell` | Untrusted input reaches a shell call |
| `wp.rce.unserialize` | Untrusted input reaches `unserialize()` |
| `wp.rce.unserialize-stored` | Stored data reaches `unserialize()` |
| `wp.lfi.dynamic-include` | Untrusted input reaches `include` or `require` |
| `wp.path.file-read` | Untrusted input reaches a file read path |
| `wp.path.file-write` | Untrusted input reaches a file write path |

### Requests and headers

| Rule | Reports |
|------|---------|
| `wp.ssrf.remote-request` | Untrusted input decides the URL of an outbound request |
| `wp.redirect.open-redirect` | Untrusted input decides a redirect target |
| `wp.header.injection` | Untrusted input decides a response header |
| `wp.ldap.injection` | Untrusted input reaches an LDAP filter |

### Storage

| Rule | Reports |
|------|---------|
| `wp.stored.untrusted-write` | Unsanitised input written to an option or meta (`--stored-taint-writes`) |
| `wp.input.setting-without-sanitize` | `register_setting()` with no `sanitize_callback` |

Run `wp-taint registry:dump` for the full description and remediation of each.
