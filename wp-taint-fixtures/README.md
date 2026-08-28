# WordPress Taint Analyser — Fixture Suite

A labelled corpus for testing a WordPress-specific taint analyser. Every
expected finding is annotated inline (Semgrep-compatible), extracted into a
machine-readable `manifest.json`, and scorable against a SARIF or JSON run with
`tools/score.py`.

- **109 annotations** across **18 rule IDs**
- **64** expected true positives, **44** expected true negatives, **1** stretch case
- Six categories: input-only, output-only, full flows, post-escape mutation,
  cross-component, and CVE-pattern-inspired

## Layout

| Dir | What it tests |
|-----|---------------|
| `01-input/` | Source recognition and sanitiser allowlisting (input side only) |
| `02-output/` | Sink recognition and escaper-context correctness (output side only) |
| `03-flows/` | Source-to-sink flows: reflected, stored, SQLi, interprocedural, callbacks |
| `04-post-escape-mutation/` | House rule: escape voided when output becomes re-mutable |
| `05-cross-component/` | Taint crossing plugin/theme boundaries via hooks and options |
| `06-cve-inspired/` | Vulnerability *classes* common in the WP ecosystem (no real plugin code) |

## Annotation grammar

On the line directly above the finding:

- `// ruleid: <rule>` — expected true positive (must be reported)
- `// ok: <rule>` — expected true negative (must NOT be reported)
- `// todoruleid: <rule>` — known miss, informational, not scored as failure
- `// todook: <rule>` — known false positive, informational

## Usage

```bash
# 1. rebuild ground truth after editing fixtures
python3 tools/build_manifest.py

# 2. run YOUR analyser over this directory, emitting SARIF or JSON
your-analyser scan wp-taint-fixtures/ --sarif > run.sarif

# 3. score the run
python3 tools/score.py run.sarif            # position match, ±2 lines
python3 tools/score.py run.sarif --by-rule  # also require the rule id to match
```

`score.py` exits non-zero if any expected positive is missed or any expected
negative is flagged, so it drops into CI directly.

See `REPORT.md` for the per-fixture breakdown of what each case tests and why.
