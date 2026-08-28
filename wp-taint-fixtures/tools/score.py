#!/usr/bin/env python3
"""Score a taint-analyser run against the fixture manifest.

Usage:
    python3 score.py <results.sarif|results.json> [--tolerance N]

Accepts SARIF 2.1.0 (results[].locations[].physicalLocation) or a simple JSON
list of {file, line, rule}. Matches a reported finding to a manifest entry when
file paths align and the reported line is within --tolerance lines of the
expected finding line (default 2, since a sink can span a few lines).

Outputs per-rule and overall TP / FP / FN with precision, recall, F1, and a
non-zero exit code if any expected-positive is missed or any expected-negative
is flagged.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def load_manifest():
    return json.loads((ROOT / 'manifest.json').read_text())

def norm(p: str) -> str:
    p = p.replace('\\', '/')
    # keep path relative to the fixtures root if possible
    for marker in ('wp-taint-fixtures/',):
        if marker in p:
            return p.split(marker, 1)[1]
    return p.lstrip('./')

def load_results(path: Path):
    data = json.loads(path.read_text())
    findings = []
    if isinstance(data, dict) and 'runs' in data:  # SARIF
        for run in data.get('runs', []):
            for res in run.get('results', []):
                rule = res.get('ruleId', '')
                for loc in res.get('locations', []):
                    phys = loc.get('physicalLocation', {})
                    uri = phys.get('artifactLocation', {}).get('uri', '')
                    line = phys.get('region', {}).get('startLine')
                    findings.append((norm(uri), line, rule))
    elif isinstance(data, list):  # simple JSON
        for r in data:
            findings.append((norm(r['file']), r.get('line'), r.get('rule', '')))
    else:
        print("Unrecognised results format", file=sys.stderr)
        sys.exit(2)
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('results')
    ap.add_argument('--tolerance', type=int, default=2)
    ap.add_argument('--by-rule', action='store_true', help='match on rule id too')
    args = ap.parse_args()

    manifest = load_manifest()
    findings = load_results(Path(args.results))

    positives = [e for e in manifest['entries'] if e['expected_positive']]
    negatives = [e for e in manifest['entries'] if e['expected_negative']]

    def reported_at(entry):
        for (f, line, rule) in findings:
            if f != norm(entry['file']):
                continue
            if line is None or entry['finding_line'] is None:
                continue
            if abs(line - entry['finding_line']) <= args.tolerance:
                if args.by_rule and rule and rule != entry['rule']:
                    continue
                return True
        return False

    tp = [e for e in positives if reported_at(e)]
    fn = [e for e in positives if not reported_at(e)]
    fp = [e for e in negatives if reported_at(e)]  # flagged a safe line
    tn = [e for e in negatives if not reported_at(e)]

    per_rule = defaultdict(lambda: dict(tp=0, fn=0, fp=0, tn=0))
    for e in tp: per_rule[e['rule']]['tp'] += 1
    for e in fn: per_rule[e['rule']]['fn'] += 1
    for e in fp: per_rule[e['rule']]['fp'] += 1
    for e in tn: per_rule[e['rule']]['tn'] += 1

    def prf(tpn, fpn, fnn):
        prec = tpn / (tpn + fpn) if (tpn + fpn) else 1.0
        rec = tpn / (tpn + fnn) if (tpn + fnn) else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return prec, rec, f1

    print(f"{'rule':<34} {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3}  {'prec':>5} {'rec':>5} {'f1':>5}")
    print('-' * 72)
    for rule in sorted(per_rule):
        c = per_rule[rule]
        p, r, f = prf(c['tp'], c['fp'], c['fn'])
        print(f"{rule:<34} {c['tp']:>3} {c['fn']:>3} {c['fp']:>3} {c['tn']:>3}  {p:>5.2f} {r:>5.2f} {f:>5.2f}")
    print('-' * 72)
    P, R, F = prf(len(tp), len(fp), len(fn))
    print(f"{'OVERALL':<34} {len(tp):>3} {len(fn):>3} {len(fp):>3} {len(tn):>3}  {P:>5.2f} {R:>5.2f} {F:>5.2f}")

    if fn:
        print(f"\nMISSED (false negatives) — {len(fn)}:")
        for e in fn:
            print(f"  {e['file']}:{e['finding_line']}  {e['rule']}")
    if fp:
        print(f"\nFALSE ALARMS (false positives) — {len(fp)}:")
        for e in fp:
            print(f"  {e['file']}:{e['finding_line']}  {e['rule']}")

    sys.exit(1 if (fn or fp) else 0)

if __name__ == '__main__':
    main()
