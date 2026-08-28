#!/usr/bin/env python3
from pathlib import Path
import json, re, sys
root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'manifest.json').read_text())
errors = []
seen = set()
for sc in manifest['scenarios']:
    sid = sc['id']
    if sid in seen: errors.append(f'duplicate scenario id: {sid}')
    seen.add(sid)
    for variant in ('vulnerable','safe'):
        base = root / 'fixtures' / sc['category'] / sid / variant
        expected_path = base / 'expected.json'
        if not expected_path.exists():
            errors.append(f'missing {expected_path}')
            continue
        expected = json.loads(expected_path.read_text())
        php_files = list(base.rglob('*.php'))
        if not php_files: errors.append(f'no PHP files for {sid}/{variant}')
        sink_markers = []
        for path in php_files:
            for n, line in enumerate(path.read_text().splitlines(), 1):
                m = re.search(r'@wp-taint-sink\s+(\w+)\s+expect=([\w.]+)', line)
                if m: sink_markers.append((path.relative_to(base).as_posix(), n, m.group(1), m.group(2)))
        if not sink_markers: errors.append(f'no sink marker for {sid}/{variant}')
        if any(x[2] != sid for x in sink_markers): errors.append(f'wrong fixture id in marker for {sid}/{variant}')
        reports = [x for x in sink_markers if x[3] != 'clean']
        if variant == 'vulnerable' and not reports: errors.append(f'vulnerable variant has no finding: {sid}')
        if variant == 'safe' and reports: errors.append(f'safe variant unexpectedly expects finding: {sid}')
if errors:
    print('Suite validation FAILED')
    for e in errors: print(' -', e)
    sys.exit(1)
print(f"Suite validation passed: {len(manifest['scenarios'])} scenarios / {len(manifest['scenarios'])*2} variants")
