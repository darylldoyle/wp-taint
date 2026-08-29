# Troubleshooting

Common problems, what causes them, and what to do.

## The scan looks like it has hung

**Symptom.** Nothing on screen for several seconds after you press enter.

**Cause.** Walking the directory tree, before any file has been parsed. On a
WordPress install with tens of thousands of files this is genuinely slow.

**Solution.** wp-taint reports each phase once a scan has been running for
250 ms:

```
Finding files…
Parsing 926/926 [============================] 100%
Indexing symbols 926/926 [====================] 100%
Building the hook and call graphs…
Structural rules 926/926 [===================] 100%
Resolving taint across functions… round 6
```

Progress is drawn on stderr, and only when stderr is a terminal, so piping and
`-o file` are unaffected. If you see nothing at all:

- Output is redirected or piped. That is intended.
- The scan finished in under 250 ms.

If a phase sits still for minutes, it is almost always `--include-path` pointed
at something enormous. See
[Scan your own code inside a WordPress install](scanning-a-wordpress-project.md#reference-a-parent-directory-safely).

## warning: Taint fixed point did not converge

**Symptom.**

```
warning: Taint fixed point did not converge within 64 iterations.
  includes/classes/PostCardHelper.php  Acme\PostCardHelper::__construct()
```

**Cause.** Two operations disagreeing about one value, so the analysis never
settles. Results for that function are incomplete: a real finding inside it may
be missed.

**Solution.** It is a bug in wp-taint, not in your code. The warning names the
file and function so it can be reported. Everything outside that function is
unaffected, and the rest of the scan is still valid.

## Findings in code I did not write

**Symptom.** Findings in `vendor/`, `node_modules/` or a third-party plugin.

**Cause.** Those paths are in the reported set.

**Solution.** Either exclude them, or move them to the context list:

```bash
wp-taint scan ./src --exclude='*/vendor/*' --exclude='*/node_modules/*'
```

```bash
wp-taint scan ./themes/mine --include-path=./plugins/third-party
```

`--exclude` skips a tree entirely. `--include-path` still reads it for symbols,
which keeps flows through it traceable while reporting only on your code.

## Duplicate findings from build output

**Symptom.** The same finding at the same line in both `src/` and `dist/`.

**Cause.** Compiled output ships alongside its source and both are scanned.

**Solution.** Exclude the build directory:

```bash
wp-taint scan ./plugin --exclude='*/dist/*' --exclude='*/build/*'
```

## N hook registrations could not be resolved to a callback

**Symptom.** A line at the end of the report.

**Cause.** `add_action()` or `add_filter()` was called with a hook name or
callback the engine could not resolve to a value, usually because it is built at
runtime.

**Solution.** Informational. It means some hook edges are missing, so a flow
through those callbacks is not traced. Nothing is wrong with your code and
nothing needs changing.

## This path crossed something the engine could not resolve

**Symptom.** That sentence under a finding.

**Cause.** An unmodelled or dynamic call in the middle of the trace, so the
result is a best effort rather than a proof.

**Solution.** Treat it as a lead rather than a verdict. Run `explain` on the
sink line to see exactly where the engine stopped:

```bash
wp-taint explain ./src/file.php:47 --scope=./src
```

## A finding I believe is wrong

**Symptom.** The code looks correct.

**Cause.** Sometimes a false positive, and sometimes a real gap the code hides.
`wp_sprintf()` is the usual surprise: it looks like `sprintf()` and runs
`apply_filters( 'wp_sprintf', … )` internally, so escaping applied to its
arguments happens before a filter.

**Solution.** Ask why, then record the answer:

```bash
wp-taint explain ./src/file.php:47 --scope=./src
```

If it is genuinely wrong, suppress it with a reason:

```php
// wp-taint-ignore-next-line wp.xss.unescaped-output -- value is an integer id, reviewed 2026-08
echo $id;
```

Reports of a false positive are worth filing with the `explain` output attached.

## Code I expected to be flagged was not

**Symptom.** A bug you know about is missing from the report.

**Cause.** Usually one of: the flow crosses something unmodelled, the file was
excluded, or an escaper the engine credits is applied somewhere you did not
notice.

**Solution.** `explain` answers this directly, and says which of those it was:

```bash
wp-taint explain ./src/file.php:47 --scope=./src
```

Check the scanned file count in the summary line too. If it is lower than you
expect, an `--exclude` is catching more than intended.

## Allowed memory size exhausted

**Symptom.**

```
PHP Fatal error: Allowed memory size of 536870912 bytes exhausted
```

**Cause.** The default `memory_limit` is not enough for a large tree. The whole
program is held in memory at once, by design, because taint crosses files.

**Solution.**

```bash
php -d memory_limit=4G vendor/bin/wp-taint scan ./src
```

Referencing fewer trees reduces peak memory more than anything else.

## --jobs seems to be ignored

**Symptom.** `--jobs=4` runs no faster than `--jobs=1`.

**Cause.** `ext-pcntl` is not loaded. Workers are processes, not threads.

**Solution.** Check with `php -m | grep pcntl`. Without it, the scan is correct
but single-process.

## Worker processes exited abnormally

**Symptom.**

```
Worker processes 0, 1, 2, 3 exited abnormally. Re-run with --jobs=1.
```

**Cause.** Usually memory pressure, often from several scans at once.

**Solution.** Lower `--jobs`, raise `memory_limit`, or run one scan at a time.
`--jobs=1` always produces the same findings; the split is a speed decision
only.

## Exit code 2 with no findings

**Symptom.** The scan reports nothing but exits 2.

**Cause.** A file failed to parse. wp-taint never silently skips a file, because
a scan that quietly looked at less than you think is the worst way to be wrong.

**Solution.** List them:

```bash
wp-taint scan ./src --parse-report
```

Then exclude the file if it is not yours, or fix the syntax if it is.

## Related

- [CLI reference](cli-reference.md)
- [Known limitations](../KNOWN_LIMITATIONS.md) for behaviour that is deliberate
