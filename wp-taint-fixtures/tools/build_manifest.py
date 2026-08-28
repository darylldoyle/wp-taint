#!/usr/bin/env python3
"""Extract ground-truth annotations from fixture files into a manifest.

Annotation grammar (Semgrep-compatible), on the line ABOVE the finding line:
    ruleid: <rule>       expected true positive  (must be reported)
    ok: <rule>           expected true negative  (must NOT be reported)
    todoruleid: <rule>   known miss, not yet expected (informational)
    todook: <rule>       known false positive, not yet expected (informational)

The finding line is the next non-comment, non-blank source line.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANNOT = re.compile(r'//\s*(ruleid|ok|todoruleid|todook):\s*([\w.\-]+)')

def is_code_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.startswith('//') or s.startswith('*') or s.startswith('/*') or s.startswith('#'):
        return False
    return True

def main():
    entries = []
    for path in sorted(ROOT.rglob('*.php')):
        rel = path.relative_to(ROOT).as_posix()
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            m = ANNOT.search(line)
            if not m:
                continue
            kind, rule = m.group(1), m.group(2)
            # find the next code line
            target_line = None
            for j in range(i + 1, len(lines)):
                if is_code_line(lines[j]):
                    target_line = j + 1  # 1-indexed
                    break
            entries.append({
                'file': rel,
                'annotation_line': i + 1,
                'finding_line': target_line,
                'kind': kind,
                'rule': rule,
                'expected_positive': kind in ('ruleid',),
                'expected_negative': kind in ('ok',),
                'informational': kind in ('todoruleid', 'todook'),
            })
    manifest = {
        'schema': 'wp-taint-fixtures/manifest@1',
        'root': 'wp-taint-fixtures',
        'total_annotations': len(entries),
        'counts': {
            'expected_positive': sum(e['expected_positive'] for e in entries),
            'expected_negative': sum(e['expected_negative'] for e in entries),
            'informational': sum(e['informational'] for e in entries),
        },
        'rules_covered': sorted({e['rule'] for e in entries}),
        'entries': entries,
    }
    out = ROOT / 'manifest.json'
    out.write_text(json.dumps(manifest, indent=2) + '\n')
    print(f"Wrote {out} with {len(entries)} annotations")
    print(json.dumps(manifest['counts'], indent=2))
    print("Rules covered:", ", ".join(manifest['rules_covered']))

if __name__ == '__main__':
    main()
