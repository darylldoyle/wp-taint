#!/usr/bin/env python3
from pathlib import Path
import json, sys
root = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    print('usage: compare_results.py actual.json')
    raise SystemExit(2)
actual = json.loads(Path(sys.argv[1]).read_text())
expected_raw = json.loads((root / 'expected-findings.json').read_text())
expected = {(x['fixture'], x['variant'], x['expect']) for x in expected_raw if x['must_report']}
actual_set = {(x['fixture'], x['variant'], x['kind']) for x in actual}
missing = sorted(expected - actual_set)
extra = sorted(actual_set - expected)
if missing or extra:
    print('Taint regression comparison FAILED')
    if missing:
        print('\nMissing findings (false negatives):')
        for x in missing: print(' -', ' / '.join(x))
    if extra:
        print('\nUnexpected findings (false positives or changed classification):')
        for x in extra: print(' -', ' / '.join(x))
    raise SystemExit(1)
print(f'Taint regression comparison passed: {len(expected)} expected findings, no extras')
