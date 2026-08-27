# `enshrined/wp-taint` — Implementation Plan

A CLI static analysis tool that finds real XSS, SQL injection, and authorization
vulnerabilities in WordPress plugin and theme code, using interprocedural taint
analysis over an SSA control flow graph.

This document is the build spec. It is written to be handed to Claude Code and
executed phase by phase. Each phase has explicit acceptance criteria. Do not
advance to the next phase until the current phase's criteria pass.

---

## 1. Goal and non-goals

### Goal

One command, `wp-taint scan ./plugin`, that produces a low-noise list of genuine
security findings in WordPress PHP code, suitable for gating CI.

### Why this exists

Existing options each fail on WordPress in a specific way:

- **Psalm taint analysis** has a real interprocedural engine, but its precision
  depends on type inference. WordPress plugin code is untyped array soup, so the
  inference degrades and the taint graph degrades with it. It also needs a
  coherent project structure with an autoloader, which themes do not have.
- **Opengrep / Semgrep** ignore types entirely, which suits WP, but cross-function
  taint is currently limited to a single file. Interfile taint is roadmap, not
  shipped.
- **PHPStan** has no dataflow engine at all. Taint would have to be rebuilt on top
  of collectors, fighting its per-file caching and parallelism model.
- **WPCS sniffs** encode the right catalogue of WP escapers and sinks, but are
  token-based and intraprocedural, so they are noisy and miss anything crossing a
  function boundary.

This tool takes the SSA/CFG approach (which gives interprocedural taint cheaply),
the WPCS catalogue (which is the expensive, already-curated asset), and a
configurable registry design.

### Non-goals

Explicitly out of scope for v1. Do not build these.

- General-purpose PHP linting, type checking, or style enforcement.
- Dependency/CVE scanning. `composer audit` already does this.
- Any runtime or dynamic analysis.
- Support for languages other than PHP.
- Any LLM or AI on the analysis path. The engine must be fully deterministic.
- A hosted service, dashboard, or daemon.

### Design principles

These are non-negotiable and should be applied when resolving any ambiguity in
this spec.

1. **Deterministic.** Same input always produces byte-identical output. Findings
   are sorted by file, then line, then column, then rule ID. No randomness, no
   hash-order iteration, no timestamps in machine-readable output.
2. **Fail loudly, never silently.** A file that fails to parse is a reported
   error, not a skipped file. Silent false negatives are the worst failure mode a
   security scanner can have.
3. **Structure carries the value.** The catalogue is data (TOML), not code. Adding
   a new WP sanitiser must never require a code change.
4. **False positives are the product risk.** A tool that cries wolf gets muted and
   then deleted. When in doubt between a false positive and a false negative,
   document the gap and take the false negative, but record it in
   `KNOWN_LIMITATIONS.md`.

---

## 2. Success criteria

The project is done when all of these hold:

- `composer require --dev enshrined/wp-taint && vendor/bin/wp-taint scan ./src` works
  with zero configuration on a WordPress plugin.
- The fixture suite (Phase 0) passes at **100% on `safe/`** (zero false positives)
  and **≥90% on `vulnerable/`** (true positive rate).
- Parse rate on the real-plugin corpus is **≥99.5%** of files, with every failure
  individually reported.
- A 50k-line plugin scans in **under 60 seconds** on a single core.
- SARIF output loads in GitHub code scanning without error.

---

## 3. Stack and dependencies

```json
{
  "require": {
    "php": ">=8.2",
    "ircmaxell/php-cfg": "^0.2",
    "nikic/php-parser": "^5.0",
    "symfony/console": "^7.0",
    "yosymfony/toml": "^1.0"
  },
  "require-dev": {
    "pestphp/pest": "^3.0",
    "phpstan/phpstan": "^2.0"
  }
}
```

Notes:

- Pin `ircmaxell/php-cfg` to whatever the current stable constraint resolves to,
  then verify it pulls `nikic/php-parser` v5. If it pulls v4, stop and report.
- `php-cfg` is MIT licensed but thinly maintained (roughly 10 open issues, 8 open
  PRs, no full-time owner). Vendor it behind our own thin adapter interface
  (`Enshrined\WpTaint\Cfg\CfgBuilder`) so that forking or replacing it later touches
  one file.
- TOML parser choice is not load-bearing. If `yosymfony/toml` is awkward, swap for
  a YAML config using `symfony/yaml`. Decide in Phase 2 and record the decision.

---

## 4. Repository layout

```
wp-taint/
├── bin/
│   └── wp-taint                      # console entrypoint
├── src/
│   ├── Cli/
│   │   ├── Application.php
│   │   └── Command/
│   │       ├── ScanCommand.php
│   │       └── DumpCfgCommand.php
│   ├── Cfg/
│   │   ├── CfgBuilder.php            # adapter over PHPCfg\Parser
│   │   └── ParseResult.php           # script | parse error, never silent
│   ├── Registry/
│   │   ├── Registry.php
│   │   ├── RegistryLoader.php
│   │   ├── Source.php
│   │   ├── Sink.php
│   │   ├── Sanitizer.php
│   │   └── Propagator.php
│   ├── Taint/
│   │   ├── TaintKind.php             # enum
│   │   ├── TaintSet.php              # immutable set
│   │   ├── TaintState.php            # SplObjectStorage<Operand, TaintSet>
│   │   ├── IntraproceduralAnalyzer.php
│   │   ├── SummaryExtractor.php
│   │   ├── FunctionSummary.php
│   │   ├── CallGraph.php
│   │   └── InterproceduralResolver.php
│   ├── Rules/
│   │   ├── StructuralRule.php        # interface
│   │   └── Wordpress/
│   │       ├── MissingRestPermissionCallback.php
│   │       ├── MissingAjaxCapabilityCheck.php
│   │       └── UnpreparedWpdbQuery.php
│   ├── Finding/
│   │   ├── Finding.php
│   │   ├── TraceStep.php
│   │   ├── Severity.php
│   │   └── FindingCollection.php
│   ├── Baseline/
│   │   ├── Baseline.php
│   │   └── BaselineWriter.php
│   └── Report/
│       ├── Reporter.php              # interface
│       ├── ConsoleReporter.php
│       ├── JsonReporter.php
│       ├── SarifReporter.php
│       └── HtmlReporter.php
├── registries/
│   ├── php-core.toml
│   ├── wordpress.toml
│   └── wordpress-vip.toml
├── tests/
│   ├── Fixtures/
│   │   ├── vulnerable/
│   │   ├── safe/
│   │   └── corpus/                   # gitignored, real plugins
│   ├── Unit/
│   └── Feature/
├── KNOWN_LIMITATIONS.md
└── README.md
```

---

## 5. Architecture

### Pipeline

```
file paths
  → CfgBuilder (nikic/php-parser → PHPCfg\Parser → PHPCfg\Script in SSA form)
  → PHPCfg\Visitor\Simplifier          (collapse redundant blocks / phi nodes)
  → PHPCfg\Visitor\DeclarationFinder   (locate functions, methods, closures)
  → Pass 1: SummaryExtractor           (per-function taint summary, no callers)
  → Pass 2: InterproceduralResolver    (call graph + worklist fixed point)
  → Pass 3: StructuralRules            (non-taint pattern checks)
  → FindingCollection (sorted, deduplicated, baseline-filtered)
  → Reporter
```

### Why SSA is the whole trick

Taint analysis over a raw AST requires implementing reaching-definitions
yourself, which is the majority of the work and the majority of the bugs. SSA
gives def-use chains for free: every operand knows the operations that wrote it
and the operations that read it. Propagation becomes a worklist walk over those
existing edges. Phi nodes handle branch and loop merges by unioning their inputs,
so control flow is handled by the IR rather than by hand.

Expect the core propagation loop to be roughly 300 lines, not 3,000. If it is
growing past that, the design has drifted.

### CRITICAL: verify the php-cfg API before writing against it

The class and property names below are the expected shape, but **do not trust
them**. In Phase 1, read the actual installed source under
`vendor/ircmaxell/php-cfg/lib/PHPCfg/` and confirm every symbol you intend to
use. Write down the real API in `docs/php-cfg-api-notes.md`.

Expected shape (verify each):

- `PHPCfg\Parser` — constructed with a `PhpParser\Parser` instance from
  `(new PhpParser\ParserFactory)->createForNewestSupportedVersion()`.
- `PHPCfg\Script` — has a main block and a collection of declared functions.
- `PHPCfg\Block` — a basic block containing an ordered list of `Op` objects.
- `PHPCfg\Traverser` and `PHPCfg\Visitor` — the extension point. Our analysis
  passes are visitors.
- Operands: `PHPCfg\Operand\Temporary` (SSA values, carrying writer ops and
  reader usages), `PHPCfg\Operand\Literal`, `PHPCfg\Operand\Variable`,
  `PHPCfg\Operand\BoundVariable`.
- Ops of interest: function calls, method calls, static calls, concatenation,
  string interpolation, echo/print terminals, phi nodes, assignments, array
  dimension fetches, property fetches, include/require.

The exact accessor names for "which ops wrote this operand" and "which ops read
this operand" are the single most important thing to confirm. The entire
propagation loop depends on them.

---

## 6. Core data model

### `TaintKind` (enum)

```php
enum TaintKind: string {
    case Html        = 'html';         // XSS
    case HtmlAttr    = 'html_attr';    // attribute context, stricter than Html
    case Sql         = 'sql';
    case Shell       = 'shell';
    case Path        = 'path';         // LFI / RFI / traversal
    case Url         = 'url';          // open redirect, SSRF
    case Header      = 'header';       // header injection
    case Eval        = 'eval';         // RCE
    case Unserialize = 'unserialize';  // object injection
    case Ldap        = 'ldap';
    case Xpath       = 'xpath';
}
```

Taint must **never** be modelled as a boolean. `esc_html()` clears HTML taint and
does nothing whatsoever for SQL. `$wpdb->prepare()` clears SQL and nothing else. A
boolean model produces an unusable noise machine. This is the single most
important modelling decision in the project.

### `TaintSet`

Immutable set of `TaintKind`. Operations: `union`, `clear(TaintKind ...$kinds)`,
`clearAll()`, `has`, `isEmpty`, `equals`. Back it with an int bitmask for speed;
the fixed point compares sets on every iteration.

### `TaintState`

Maps operands to taint sets for one function body.
`SplObjectStorage<Operand, TaintSet>`, plus the provenance needed to reconstruct a
trace: for each tainted operand, the op that introduced or propagated the taint
and the predecessor operand.

### `FunctionSummary`

Describes a function's taint behaviour independent of any caller. This is what
makes the analysis interprocedural without being exponential.

```php
final class FunctionSummary {
    public string $fqn;

    /** @var array<int, TaintSet> param index → kinds that reach the return value */
    public array $paramToReturn;

    /** @var array<int, list<SinkReference>> param index → sinks it reaches */
    public array $paramToSink;

    /** @var array<int, TaintSet> param index → kinds this function clears */
    public array $clears;

    /** kinds this function introduces regardless of arguments */
    public TaintSet $introduces;

    /** true if any parameter reaches a return via an unresolved path */
    public bool $imprecise;
}
```

### `Finding`

```php
final class Finding {
    public string $ruleId;          // e.g. "wp.xss.unescaped-output"
    public Severity $severity;
    public TaintKind $kind;
    public string $file;
    public int $line;
    public int $column;
    public string $message;
    /** @var list<TraceStep> source → sink, in order */
    public array $trace;
    public string $fingerprint;     // stable hash for baselining
}
```

`fingerprint` must be stable across line-number changes. Hash the rule ID, the
file path relative to project root, the sink function name, and a normalised
snippet — **not** the raw line number. Otherwise the baseline invalidates on every
unrelated edit.

### `TraceStep`

`file`, `line`, `column`, `description`. The trace is not optional. A finding that
says "tainted" without showing the path from source to sink is a finding nobody
acts on, and it makes triage impossible.

---

## 7. Registry format

The registry is data. Adding a WP function must never require touching PHP code.

### Schema

```toml
[meta]
name = "wordpress"
extends = ["php-core"]
description = "WordPress core sources, sinks, sanitizers"

# ---------- SOURCES ----------

[[sources]]
superglobal = "_GET"
kinds = ["html", "html_attr", "sql", "shell", "path", "url", "header", "eval"]

[[sources]]
function = "get_post_meta"
kinds = ["html", "html_attr", "sql"]
note = "Second-order taint. Stored XSS lives here."

[[sources]]
class = "WP_REST_Request"
method = "get_param"
kinds = ["html", "html_attr", "sql", "shell", "path", "url"]

# ---------- SANITIZERS ----------

[[sanitizers]]
function = "esc_html"
arg = 0
clears = ["html"]

[[sanitizers]]
function = "absint"
arg = 0
clears = ["*"]                       # integer cast clears everything

[[sanitizers]]
class = "wpdb"
method = "prepare"
arg = 0
clears = ["sql"]
requires_literal_arg = 0             # see below

# ---------- PROPAGATORS ----------

[[propagators]]
function = "wp_unslash"
arg = 0
note = "Pass-through. NOT a sanitizer. Do not move this to [[sanitizers]]."

# ---------- SINKS ----------

[[sinks]]
construct = "echo"
kind = "html"
severity = "high"
rule_id = "wp.xss.unescaped-output"

[[sinks]]
class = "wpdb"
method = "query"
arg = 0
kind = "sql"
severity = "critical"
rule_id = "wp.sqli.wpdb-query"
```

### `requires_literal_arg`

Special semantics, and important. `$wpdb->prepare()` only sanitises if its first
argument is a literal string containing placeholders. If the first argument is
itself interpolated or concatenated from a variable, `prepare()` provides no
protection and the call is a sink, not a sanitiser. The engine must check this.
This is a real and common WordPress bug class.

### Loading and precedence

- `--registry=wordpress` loads `registries/wordpress.toml`, which `extends`
  `php-core.toml`. Later definitions override earlier ones by
  function/method key.
- A project-local `wp-taint.toml` in the scan root is loaded last and can add or
  override anything.
- Unknown keys in a registry file are a hard error, not a warning. Typos in a
  security catalogue silently create false negatives.

---

## 8. The WordPress catalogue

This is the starter set. Cross-check every entry against the WPCS sniffs
(`WordPress.Security.EscapeOutput`, `WordPress.Security.ValidatedSanitizedInput`,
`WordPress.DB.PreparedSQL`) and expand. WPCS is the curated source of truth for
which WP functions escape what.

### Sources

**Superglobals:** `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`.

`$_SERVER` is partially tainted. Taint only these keys:
`HTTP_*` (any), `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`, `PATH_INFO`,
`HTTP_REFERER`, `HTTP_USER_AGENT`. Treat other `$_SERVER` keys as clean, or the
false positive rate becomes unmanageable.

**Raw input:** `file_get_contents('php://input')`, `fopen('php://input', ...)`.

**WP request layer:** `WP_REST_Request::get_param`, `::get_params`,
`::get_json_params`, `::get_body`, `::get_query_params`, `get_query_var()`,
`wp_get_referer()`, `wp_get_raw_referer()`.

**Second-order / stored** (these produce stored XSS, which is most of the WP CVE
population, so do not omit them): `get_post_meta`, `get_user_meta`,
`get_term_meta`, `get_comment_meta`, `get_option`, `get_site_option`,
`get_transient`, `wpdb::get_results`, `wpdb::get_var`, `wpdb::get_row`,
`wpdb::get_col`.

Stored sources should be configurable off via `--no-stored-taint`, because on some
codebases they dominate the output and teams want to triage reflected XSS first.

### Sanitizers and escapers

| Function | Clears |
|---|---|
| `esc_html`, `esc_html__`, `esc_html_e`, `esc_html_x` | `html` |
| `esc_attr`, `esc_attr__`, `esc_attr_e`, `esc_attr_x` | `html`, `html_attr` |
| `esc_textarea` | `html` |
| `esc_js` | `html` |
| `esc_xml` | `html` |
| `esc_url` | `html`, `html_attr`, `url` |
| `esc_url_raw`, `sanitize_url` | `url` (NOT `html`) |
| `wp_kses`, `wp_kses_post`, `wp_kses_data` | `html` |
| `sanitize_text_field`, `sanitize_textarea_field` | `html` |
| `sanitize_key`, `sanitize_html_class`, `sanitize_title` | `html`, `html_attr`, `sql` |
| `sanitize_email`, `sanitize_file_name` | `html`, `path` |
| `tag_escape` | `html` |
| `absint`, `intval`, `floatval` | `*` |
| `esc_sql`, `wpdb::_real_escape` | `sql` |
| `wpdb::prepare` | `sql`, conditional on literal first arg |
| `wp_validate_redirect` | `url` |
| `wp_json_encode` | `html` only when the output is inside a `<script>` JSON context. Model as clearing `html` but flag as imprecise. |

### NOT sanitizers — common mistakes to encode explicitly

Add these as `[[propagators]]` with an explanatory `note`, so that anyone reading
the registry sees why they are not in the sanitizer list:

- **`wp_unslash`** — strips slashes only. Pure pass-through. This is the single
  most common misunderstanding in WP code review.
- **`stripslashes`**, **`trim`**, **`strtolower`**, **`substr`** — string ops,
  propagate taint.
- **`sanitize_text_field` for SQL** — it clears HTML, not SQL.
- **`esc_html` for SQL or attributes-in-URL contexts** — kind-specific.

### Sinks

**Output (`html`):** `echo`, `print`, `printf`, `vprintf`, `print_r` with second
arg falsy, `var_dump`, `_e`, `_ex`, inline HTML echo of a variable.

**SQL (`sql`, critical):** `wpdb::query`, `wpdb::get_results`, `wpdb::get_var`,
`wpdb::get_row`, `wpdb::get_col`, `wpdb::prepare` first argument.

**NOT SQL sinks** — these escape internally and flagging them is a guaranteed
false positive: `wpdb::insert`, `wpdb::update`, `wpdb::delete`, `wpdb::replace`.
Encode them explicitly as safe so nobody re-adds them later.

**RCE (`eval`, critical):** `eval`, `assert` with string arg, `create_function`,
`preg_replace` with `/e` modifier.

**Shell (`shell`, critical):** `exec`, `shell_exec`, `system`, `passthru`,
`popen`, `proc_open`, backtick operator.

**Path (`path`, high):** `include`, `include_once`, `require`, `require_once`,
`file_get_contents`, `file_put_contents`, `fopen`, `unlink`, `rename`, `copy`,
`WP_Filesystem` methods.

**Redirect (`url`, medium):** `wp_redirect`, `header('Location: ...')`.
Note `wp_safe_redirect` is the safe variant and is not a sink.

**Header (`header`, medium):** `header`, `setcookie`.

**Deserialization (`unserialize`, critical):** `unserialize`,
`maybe_unserialize`.

**Stored taint sinks** (write side of second-order): `update_option`,
`update_post_meta`, `update_user_meta`, `add_post_meta`. Only report these at low
severity, and only when `--stored-taint-writes` is enabled. Off by default.

---

## 9. Build phases

### Phase 0 — Fixture suite (BUILD THIS FIRST)

Do not write any engine code until this exists. It is the only thing that makes
every later decision verifiable, and it is reusable even if the engine approach
changes entirely.

**Tasks**

1. Create `tests/Fixtures/vulnerable/` with at least 40 PHP files, each a minimal
   reproduction of a real WordPress vulnerability class. Derive them from public
   WPScan / Patchstack advisories. Each file gets a sibling
   `<name>.expected.json` listing the expected rule IDs, kinds, and sink lines.
2. Create `tests/Fixtures/safe/` with at least 40 files that are *superficially
   similar* to the vulnerable ones but correctly escaped. These are the false
   positive tests and they matter more than the vulnerable ones.
3. Create `tests/Fixtures/parse/` with gnarly-but-valid PHP that must parse:
   alternative syntax (`if: endif;`), heredocs and nowdocs, inline HTML
   interleaving, variable variables, `list()` destructuring, `match`, enums,
   attributes, constructor promotion, first-class callable syntax, nested
   ternaries, `goto`.
4. Write a `corpus:fetch` composer script that downloads the top ~50 plugins from
   the WordPress.org repository into `tests/Fixtures/corpus/` (gitignored). This
   is the parse-rate and performance benchmark.

**Coverage required in `vulnerable/`**

- Reflected XSS: direct, via concatenation, via interpolation, via `printf`.
- Reflected XSS crossing one function boundary, and crossing two.
- Stored XSS via `get_post_meta` and via `get_option`.
- SQLi: direct interpolation into `wpdb::query`.
- SQLi: `wpdb::prepare` with a non-literal first argument.
- SQLi crossing a function boundary.
- Open redirect via `wp_redirect`.
- LFI via `include` with user input.
- RCE via `eval` and via `unserialize`.
- REST route registered with no `permission_callback`.
- REST route with `permission_callback => '__return_true'` on a write operation.
- AJAX handler with no capability check and no nonce check.

**Coverage required in `safe/`**

- Every vulnerable case above, correctly escaped, one file each.
- `wp_unslash` followed by proper sanitisation (must NOT flag).
- `absint` on a numeric parameter (must NOT flag).
- `wpdb::insert`, `update`, `delete` with user data (must NOT flag).
- `esc_html` applied inside a helper function that returns the escaped value
  (tests interprocedural sanitisation, a classic false positive source).
- `wp_safe_redirect` with user input (must NOT flag).
- Escaping applied on one branch of an if/else where the other branch is also
  escaped differently (tests phi node handling).

**Acceptance:** `composer test:fixtures` runs and reports pass/fail counts against
expectations. At this stage everything fails, which is correct. The harness works.

---

### Phase 1 — Skeleton, parsing, CFG

**Tasks**

1. Composer package scaffold. Symfony Console app at `bin/wp-taint`.
2. **Read `vendor/ircmaxell/php-cfg/lib/PHPCfg/` in full.** Write
   `docs/php-cfg-api-notes.md` documenting the real API: the Script/Block/Op
   structure, the exact accessors for operand def-use links, the available
   visitors, and what the Simplifier does. Do not skip this. Every subsequent
   phase depends on getting these names right.
3. Implement `Cfg\CfgBuilder` as a thin adapter. It takes a file path and returns
   a `ParseResult` that is either a `Script` or a structured parse error with
   file, line, and message. **It must never return null or an empty script on
   failure.**
4. Implement `wp-taint dump-cfg <file>` using php-cfg's text printer, plus
   `--format=dot` for GraphViz.
5. Run `dump-cfg` across `tests/Fixtures/parse/` and the corpus. Record the parse
   rate.

**Acceptance**

- `wp-taint dump-cfg` produces a readable SSA dump for every file in
  `tests/Fixtures/parse/`.
- Parse rate on the corpus is ≥99.5%. Every failure is listed with a reason.
- If parse rate is below 99.5%, **stop and report before continuing.** A parser
  that cannot read WordPress code makes everything downstream worthless. This is
  the project's first kill gate.

---

### Phase 2 — Registry

**Tasks**

1. Implement the TOML schema in section 7, with strict validation. Unknown keys
   are errors.
2. Implement `extends` resolution and the override precedence rules.
3. Write `registries/php-core.toml` and `registries/wordpress.toml` from the
   catalogue in section 8.
4. Write `registries/wordpress-vip.toml` extending `wordpress`, adding VIP-specific
   restrictions (direct database queries discouraged, `wpcom_vip_*` helpers, the
   VIP-specific escaping helpers).
5. `wp-taint registry:dump --registry=wordpress` prints the fully resolved
   catalogue, so a human can audit it.

**Acceptance**

- Registry loads, resolves inheritance, and validates. Malformed files produce a
  clear error naming the file, key, and line.
- `registry:dump` output is reviewed by a human against WPCS before Phase 3
  starts.

---

### Phase 3 — Intraprocedural taint

The core engine. Target roughly 300 lines for the propagation loop.

**Tasks**

1. Implement `TaintKind`, `TaintSet`, `TaintState`.
2. Implement `IntraproceduralAnalyzer`: a worklist over the SSA def-use graph
   within a single function body.
   - Seed: operands matching registry sources get their configured `TaintSet`.
   - Propagate: for each tainted operand, walk its usages. Concatenation and
     interpolation union the taint of all inputs. Assignment copies. Array
     writes taint the whole array (over-approximate; note it in limitations).
   - Phi nodes: union the taint sets of all incoming operands.
   - Sanitizers: clear the configured kinds from the result operand.
   - Propagators: pass taint through unchanged.
   - Sinks: if the operand at the configured argument index has the sink's kind,
     emit a `Finding` with the full trace.
3. Implement the `requires_literal_arg` check for `wpdb::prepare`.
4. Implement trace reconstruction by walking provenance links backwards from sink
   to source.
5. Implement `--dump-taint-graph=FILE` producing GraphViz dot output. This is the
   debugging tool you will use constantly. Build it now, not later.

**Acceptance**

- All single-function fixtures in `vulnerable/` are detected.
- All single-function fixtures in `safe/` produce zero findings.
- Every finding has a complete, correct trace.
- Fixed point terminates on all corpus files (add a per-function iteration cap
  with a loud warning if it trips).

---

### Phase 4 — Interprocedural

**Tasks**

1. Implement `SummaryExtractor`: for each function, compute a `FunctionSummary`
   assuming all parameters are tainted with all kinds, and record which kinds
   reach the return value, which reach sinks, and which get cleared.
2. Implement `CallGraph` from php-cfg's call-finding visitor. Resolve:
   - Direct function calls by name.
   - Method calls where the receiver type is statically obvious (`$wpdb`, `new
     Foo()`, `$this`).
   - Static calls.
   - Leave dynamic calls (`$fn()`, `call_user_func` with a variable)
     unresolved and mark the summary `imprecise`.
3. Implement `InterproceduralResolver`: worklist fixed point over the call graph
   in reverse topological order, instantiating summaries at each call site.
   Handle recursion by iterating to a fixed point with a cap.
4. Extend traces to cross function boundaries: "passed to `render_field()` as
   parameter 0", "returned from `render_field()`".

**Acceptance**

- Multi-function fixtures in `vulnerable/` are detected, including the two-hop
  case.
- The interprocedural sanitisation case in `safe/` produces zero findings.
- `--no-interprocedural` flag disables Phase 4 and falls back to Phase 3
  behaviour, for debugging and for speed.

---

### Phase 5 — Structural rules

Non-taint pattern checks. These catch broken authorization, which is arguably a
larger share of real WordPress CVEs than injection is, and which taint analysis
structurally cannot find.

**Tasks**

1. `StructuralRule` interface operating on the CFG (and where simpler, on the raw
   nikic AST, which `CfgBuilder` should retain alongside the Script).
2. `MissingRestPermissionCallback` — `register_rest_route` with no
   `permission_callback` key, or with `__return_true` on a non-GET method.
3. `MissingAjaxCapabilityCheck` — a callback registered via `add_action` on a
   `wp_ajax_*` or `wp_ajax_nopriv_*` hook whose body contains no
   `current_user_can`, `check_ajax_referer`, `check_admin_referer`, or
   `wp_verify_nonce` call.
4. `UnpreparedWpdbQuery` — the interpolation check, as a standalone rule as well
   as via taint.

**Note on hook resolution:** connecting `add_action('wp_ajax_x', 'handler')` to
the handler body requires resolving the callback. Handle: string function name,
`[$this, 'method']` array, `[__CLASS__, 'method']`, and closures defined inline.
Anything else, skip and count it in a "unresolved hooks" report so the gap is
visible.

**Acceptance**

- All REST and AJAX fixtures detected.
- Zero false positives on the corpus for these rules, verified by manual spot
  check of at least 20 hits.

---

### Phase 6 — Output, baseline, CLI

**Tasks**

1. `ConsoleReporter` — grouped by file, coloured by severity, trace shown
   indented. `--verbose` shows the full trace, default shows source and sink only.
2. `JsonReporter` — stable schema, versioned with a `schemaVersion` key.
3. `SarifReporter` — SARIF 2.1.0, with `codeFlows` populated from traces so GitHub
   code scanning renders the path.
4. `HtmlReporter` — self-contained single file. Reuse the existing Fueled
   `html-report` skill conventions for brand assets, the light/dark/auto theme
   system, and layout.
5. Baseline: `--generate-baseline=wp-taint-baseline.json` writes current
   fingerprints; `--baseline=FILE` suppresses them. Report a count of suppressed
   findings so the debt stays visible.
6. Inline suppression: `// wp-taint-ignore-next-line <rule-id> -- <reason>`. The
   reason is mandatory; a suppression without one is itself an error.

**CLI surface**

```
wp-taint scan <paths...>
  --registry=NAME|PATH        default: wordpress
  --config=PATH               default: ./wp-taint.toml if present
  --format=console|json|sarif|html    default: console
  --output=PATH               default: stdout
  --baseline=PATH
  --generate-baseline[=PATH]
  --min-severity=low|medium|high|critical
  --fail-on=SEVERITY          default: high
  --no-interprocedural
  --no-stored-taint
  --stored-taint-writes
  --exclude=GLOB              repeatable
  --parse-report              list files that failed to parse, then exit
  --dump-taint-graph=PATH
  --jobs=N                    default: 1

wp-taint dump-cfg <file> [--format=text|dot]
wp-taint registry:dump [--registry=NAME]
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` execution error
(including any parse failure).

**Acceptance**

- SARIF validates against the 2.1.0 schema and renders code flows in GitHub.
- Baseline round-trips: generate, re-run, zero findings reported.
- Fingerprints survive a whitespace-only reformat of the analysed file.

---

### Phase 7 — Tuning

The phase that determines whether this is used or deleted. Budget more time for
it than feels reasonable.

**Tasks**

1. Run against all 50 corpus plugins. Triage every finding by hand into: true
   positive, false positive, or unclear.
2. For each false positive, decide whether it is a registry gap (add the missing
   sanitiser) or an engine limitation (record in `KNOWN_LIMITATIONS.md`).
3. Iterate until the false positive rate on the corpus is under 10%.
4. Write `KNOWN_LIMITATIONS.md` honestly. Expected entries:
   - `include`/`require` of template files is not followed across the CFG.
   - Dynamic calls and variable variables are unresolved.
   - Array element taint is whole-array, not per-key.
   - Object property taint is per-property but not path-sensitive.
   - Filter and action callback chains (`apply_filters`) are not followed.
   - `wp_json_encode` context-sensitivity is approximated.

**Acceptance**

- False positive rate under 10% on the corpus.
- `KNOWN_LIMITATIONS.md` is complete and honest.

---

### Phase 8 — Performance

**Tasks**

1. Profile against the largest corpus plugin.
2. Cache parsed CFGs and function summaries keyed by file content hash.
3. Optional parallelism via `--jobs`, using process forking over the file list.
   Summaries must be merged deterministically regardless of completion order.

**Acceptance**

- 50k lines in under 60 seconds single-threaded.
- Warm cache re-run at least 5x faster.
- Output is byte-identical across `--jobs=1` and `--jobs=8`.

---

## 10. Guardrails

Apply these throughout. They encode mistakes that are easy to make and expensive
to discover late.

1. **Never treat `wp_unslash` as a sanitizer.** It is a propagator. If a test
   passes because `wp_unslash` cleared taint, the test is wrong.
2. **Never flag `wpdb::insert`, `update`, `delete`, `replace`.** They escape
   internally.
3. **`wpdb::prepare` only sanitises with a literal first argument.** Otherwise it
   is itself a sink.
4. **`esc_url_raw` is not an HTML escaper.** It is for redirects and database
   storage.
5. **Parse failures are errors.** Never `try { } catch { continue; }` over a file.
   Exit code 2.
6. **No LLM, no network, no telemetry in the analysis path.** Fully deterministic
   and offline.
7. **Sort all output.** File, then line, then column, then rule ID.
8. **Every finding carries a trace.** No exceptions.
9. **Do not add a rule without adding both a vulnerable and a safe fixture for
   it.** The safe fixture is the one that matters.
10. **Prefer a documented false negative to an undocumented false positive.**

---

## 11. Kill gates

Stop and report to a human at each of these, rather than pressing on.

| Gate | Condition | Action if failed |
|---|---|---|
| End of Phase 1 | Corpus parse rate ≥99.5% | Stop. php-cfg may not handle modern WP. Re-evaluate base. |
| End of Phase 3 | ≥70% of single-function vulnerable fixtures caught, zero false positives on safe | Stop. Intraprocedural precision will only get worse with interprocedural. |
| End of Phase 4 | ≥90% of all vulnerable fixtures caught | Stop. Compare against Opengrep on the same fixtures before investing further. |
| End of Phase 7 | False positive rate under 10% | Do not ship. An untuned scanner gets muted and then deleted. |

---

## 12. Benchmark against alternatives

Before Phase 5, run Opengrep with a hand-written WordPress rule pack and Psalm
with `--taint-analysis` plus `php-stubs/wordpress-stubs` against the same fixture
suite. Record all three results in `docs/benchmark.md`.

If Opengrep matches or beats this tool on the fixtures, that is a genuinely useful
finding and worth surfacing immediately rather than at the end. The fixture suite
was built first precisely so this comparison is cheap and honest.

---

# Appendix A — Output specification

Deployment context for v1: this runs **locally, on a developer machine**, not in
CI. That reprioritises Phase 6.

**Build in this order:**

1. `ConsoleReporter` — primary human interface. Phase 3.
2. `JsonReporter` — machine handoff. Phase 3, same time as console. It is the same
   data through a different serialiser and costs almost nothing.
3. `SarifReporter` — editor integration. Phase 6.
4. `--explain` mode — false-negative debugging. Phase 6.
5. `HtmlReporter` — **deferred to post-v1.** Not needed for local use. Do not
   build it in the first pass.

CI-oriented features (`--fail-on` gating, baseline) still get built, but they are
not the design centre for v1.

---

## A.1 Console reporter

### Default output

Two-line header, then source and sink only. Enough to decide whether to look
closer.

```
CRITICAL  wp.xss.unescaped-output
  includes/class-report-renderer.php:47:10  echo

    source  :42:24  $_GET['report_filter']
    sink    :47:10  echo

  Untrusted input reaches output without HTML escaping.
  Run with --verbose for the full path, or --explain for why.
```

### Verbose output (`--verbose` / `-v`)

Full trace, every step numbered, with the source line rendered inline.

```
CRITICAL  wp.xss.unescaped-output
  includes/class-report-renderer.php:47:10  echo

  Untrusted input reaches output without HTML escaping.

   1. source       includes/class-report-renderer.php:42:24
      $filter = wp_unslash( $_GET['report_filter'] );
                            ^^^^^^^^^^^^^^^^^^^^^^
      Tainted by superglobal $_GET. Kinds: html, html_attr, sql, shell,
      path, url, header, eval

   2. propagate    includes/class-report-renderer.php:42:15
      $filter = wp_unslash( $_GET['report_filter'] );
                ^^^^^^^^^^
      wp_unslash() is a pass-through. It removes slashes and does not escape.

   3. call         includes/class-report-renderer.php:47:24
      echo $this->build_header( $filter );
                                ^^^^^^^
      Passed to ReportRenderer::build_header() as parameter 0 ($label).

   4. propagate    includes/class-report-renderer.php:58:22
      return '<h2>' . $label . '</h2>';
                      ^^^^^^
      Concatenated into the return value. Summary: param 0 → return, html.

   5. sink         includes/class-report-renderer.php:47:10
      echo $this->build_header( $filter );
           ^^^^
      Reaches echo with html taint intact.

  Fix
    esc_html() at step 4, or wp_kses_post() if markup is intended.

  Suppress
    // wp-taint-ignore-next-line wp.xss.unescaped-output -- <reason>
```

### Formatting rules

- Severity is colourised: CRITICAL red, HIGH red, MEDIUM yellow, LOW dim. Respect
  `NO_COLOR` and detect non-TTY, falling back to plain text.
- File paths are relative to the scan root, so output is portable and diffable.
- Caret underlines mark the exact column span of the operand. If the span is
  unavailable, omit the caret line rather than guessing.
- Step verbs are a fixed closed set: `source`, `propagate`, `sanitize`, `call`,
  `return`, `sink`. Never free-form.
- Each `propagate` step states *why* taint survived. "wp_unslash() is a
  pass-through" teaches the reader something; "propagated" does not.
- Long traces (>12 steps) collapse the middle with `... N intermediate steps
  (--trace-full to expand)`.

### Summary footer

```
─────────────────────────────────────────────────────────
  4 critical   7 high   2 medium   0 low
  13 findings in 9 files · 412 files scanned · 3.1s
  2 findings suppressed by baseline
  1 file failed to parse (run --parse-report)
─────────────────────────────────────────────────────────
```

The parse-failure line is **always** shown when non-zero, in red, regardless of
verbosity. A silently skipped file is a silent false negative.

---

## A.2 Handing output to an agent

Do not pipe console text to an agent. Use `--format=json`.

Console output is lossy by design: colour codes, collapsed traces, truncated
spans. JSON carries the full trace, taint kinds, fingerprints, and summary
metadata, and costs no extra implementation work.

Intended usage:

```bash
wp-taint scan ./src --format=json --output=findings.json
# then hand findings.json to the agent
```

To support this, JSON output must be **self-describing**: include the rule
definition (id, title, description, remediation guidance) inline on each finding
rather than requiring a lookup table. An agent reading the file cold should need
no other context.

---

## A.3 JSON schema

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "wp-taint", "version": "0.1.0" },
  "scan": {
    "root": "/Users/dd/Sites/client-plugin",
    "registries": ["php-core", "wordpress"],
    "filesScanned": 412,
    "filesFailedToParse": 1,
    "interprocedural": true,
    "durationMs": 3104
  },
  "parseFailures": [
    { "file": "vendor/legacy/old.php", "line": 88, "message": "Syntax error, unexpected T_STRING" }
  ],
  "findings": [
    {
      "fingerprint": "a3f9c21e8b4d7056",
      "ruleId": "wp.xss.unescaped-output",
      "rule": {
        "title": "Untrusted input reaches output without HTML escaping",
        "description": "A value derived from user-controlled input reaches an output construct with html taint intact.",
        "remediation": "Apply esc_html() for text, esc_attr() for attribute values, or wp_kses_post() where limited markup is intended.",
        "cwe": "CWE-79"
      },
      "severity": "critical",
      "kind": "html",
      "location": { "file": "includes/class-report-renderer.php", "line": 47, "column": 10, "endColumn": 14 },
      "message": "Untrusted input reaches output without HTML escaping.",
      "imprecise": false,
      "trace": [
        {
          "step": 1,
          "verb": "source",
          "file": "includes/class-report-renderer.php",
          "line": 42, "column": 24, "endColumn": 46,
          "snippet": "$filter = wp_unslash( $_GET['report_filter'] );",
          "description": "Tainted by superglobal $_GET.",
          "kinds": ["html", "html_attr", "sql", "shell", "path", "url", "header", "eval"]
        },
        {
          "step": 2,
          "verb": "propagate",
          "file": "includes/class-report-renderer.php",
          "line": 42, "column": 15, "endColumn": 25,
          "snippet": "$filter = wp_unslash( $_GET['report_filter'] );",
          "description": "wp_unslash() is a pass-through. It removes slashes and does not escape.",
          "kinds": ["html", "html_attr", "sql", "shell", "path", "url", "header", "eval"]
        },
        {
          "step": 3,
          "verb": "call",
          "file": "includes/class-report-renderer.php",
          "line": 47, "column": 24, "endColumn": 31,
          "snippet": "echo $this->build_header( $filter );",
          "description": "Passed to ReportRenderer::build_header() as parameter 0 ($label).",
          "callee": "ReportRenderer::build_header",
          "parameterIndex": 0,
          "kinds": ["html", "html_attr", "sql", "shell", "path", "url", "header", "eval"]
        },
        {
          "step": 4,
          "verb": "propagate",
          "file": "includes/class-report-renderer.php",
          "line": 58, "column": 22, "endColumn": 28,
          "snippet": "return '<h2>' . $label . '</h2>';",
          "description": "Concatenated into the return value.",
          "kinds": ["html"]
        },
        {
          "step": 5,
          "verb": "sink",
          "file": "includes/class-report-renderer.php",
          "line": 47, "column": 10, "endColumn": 14,
          "snippet": "echo $this->build_header( $filter );",
          "description": "Reaches echo with html taint intact.",
          "kinds": ["html"]
        }
      ]
    }
  ]
}
```

Rules:

- `findings` sorted by file, line, column, ruleId. Byte-identical across runs.
- No timestamps anywhere. `durationMs` lives under `scan` and is excluded from any
  diffing or golden-file test.
- `imprecise: true` when any step in the trace crossed an unresolved dynamic call
  or an over-approximated array write. Consumers can filter on it.
- `kinds` is present on every step, so a reader can see exactly where a sanitiser
  narrowed the set.

---

## A.4 SARIF reporter

SARIF renders well locally, which makes it worth building even without CI.

**Viewer recommendation:** Trail of Bits' **SARIF Explorer** for VS Code. It shows
data flow browsable from source to sink, and adds triage: classify each result as
Bug or False Positive with keyboard shortcuts (right arrow / left arrow), add
comments, and export the triaged set.

That triage workflow is precisely what Phase 7 needs. Corpus triage in SARIF
Explorer instead of a spreadsheet will save days.

Microsoft's **SARIF Viewer** extension is the simpler alternative: squiggles in
source, entries in the Problems list, and a dedicated results panel with
grouping and filtering. It strictly supports SARIF 2.1.0 only.

**Requirements:**

- SARIF 2.1.0. No older versions.
- Populate `runs[].results[].codeFlows[].threadFlows[].locations[]` from the
  trace, in order. This is the structure both viewers read to render the
  source-to-sink walk. **Emitting SARIF without `codeFlows` wastes the format** —
  it degrades to a flat list no better than the console output.
- Each thread flow location carries `message.text` (the step description),
  `location.physicalLocation.region` with `startLine`, `startColumn`,
  `endColumn`, and `nestingLevel: 0`.
- `runs[].tool.driver.rules[]` holds full rule metadata: `id`, `name`,
  `shortDescription`, `fullDescription`, `help.markdown` with remediation,
  `properties.tags` including the CWE, and `defaultConfiguration.level`.
- Severity maps: critical and high → `error`, medium → `warning`, low → `note`.
  SARIF has no `critical`; carry the real severity in
  `properties.problemSeverity` and `properties.securitySeverity` (a 0.0–10.0
  numeric, which drives sort order in most viewers).
- `originalUriBaseIds` set to the scan root so viewers resolve relative paths to
  the local workspace without prompting.
- `partialFingerprints.wpTaintFingerprint` set to our fingerprint, so viewers and
  future tooling can track a finding across edits.

**Acceptance for this reporter:**

- Output validates against the published SARIF 2.1.0 JSON schema.
- Opening the file in VS Code with SARIF Explorer shows every finding with a
  clickable, ordered source-to-sink flow, and every step navigates to the correct
  line and column.
- Opening the same file with Microsoft's SARIF Viewer shows squiggles on the sink
  lines with no schema errors.

---

## A.5 `--explain` mode

The answer to "why was this **not** flagged". Given that the primary risk with
this tool is false negatives, this is arguably more valuable than any report
format. Build it in Phase 6.

```
wp-taint explain <file>:<line> [--kind=html|sql|...]
```

It runs the normal analysis, then reports the taint state at that location and
why it is what it is.

**Case 1 — taint died at a sanitiser**

```
includes/class-report-renderer.php:58

  return '<h2>' . $label . '</h2>';

  $label at this point carries: (none)

  Taint reached this function but was cleared upstream:
    :47:24  esc_html( $filter )  cleared [html] before the call

  No finding is expected here for kind=html.
```

**Case 2 — no source ever reached it**

```
  $label at this point carries: (none)

  No tainted value reaches this location.
  ReportRenderer::build_header is called from 2 sites:
    :47:24   argument is a literal string
    :91:12   argument derives from get_the_title(), not a configured source

  If get_the_title() should be treated as tainted, add it to
  registries/wordpress.toml under [[sources]].
```

**Case 3 — the path was cut by an engine limitation**

```
  $label at this point carries: (none)

  A potential path was abandoned:
    :83:9   call to $callback( $value ) could not be resolved
            (dynamic call, variable callee)

  This is a known limitation. See KNOWN_LIMITATIONS.md § dynamic-calls.
  Re-run with --assume-dynamic-tainted to over-approximate.
```

Case 3 is the important one. It converts "I do not trust this tool" into a
specific, checkable statement about what the engine did and did not do.

`--assume-dynamic-tainted` is a global flag worth adding alongside: treat every
unresolved dynamic call as propagating all taint. Noisy, but it gives an upper
bound on what the tool might be missing, which is exactly what you want when
auditing the auditor.
