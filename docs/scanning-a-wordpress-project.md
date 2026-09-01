# Scan your own code inside a WordPress install

Point wp-taint at the handful of directories you wrote, and let it read the
plugins around them for context without reporting on any of them.

A WordPress checkout is mostly code you did not write. The interesting shape is
two or three first-party directories inside an install of thousands of
third-party files, and those directories usually reference each other: a client
platform plugin and the themes built against it are one program, not three
scans.

**Prerequisites:** wp-taint installed, and a WordPress checkout on disk.

## Report on several directories at once

Pass every directory you want reported on as an argument. They are analysed
together as one program, so a theme calling into a shared plugin resolves.

```bash
WPC=/path/to/wp-content

wp-taint scan \
  $WPC/themes/client-org-theme \
  $WPC/themes/client-news-theme \
  $WPC/plugins/client-shared
```

The paths list is the reported set. Findings are anchored at the deepest
directory common to all of them, so with the three targets above they read as
`themes/client-org-theme/functions.php:12`. Scan a single directory and paths
are relative to that directory instead.

## Add context without adding findings

`--include-path` names a tree that is parsed and summarised for its symbols but
never reported on. Repeat it once per tree.

```bash
wp-taint scan \
  $WPC/themes/client-org-theme \
  $WPC/plugins/client-shared \
  --include-path=$WPC/plugins/co-authors-plus \
  --include-path=$WPC/client-mu-plugins
```

Two lists, two jobs:

| List | Flag | Analysed | Reported |
|------|------|----------|----------|
| Targets | positional arguments | yes | yes |
| Context | `--include-path` | yes | no |

A referenced tree still contributes everything the engine needs. If
`co-authors-plus` defines a function your theme echoes, the flow through it is
traced and the finding is raised **in your theme**, where you can fix it.

Inheritance crosses the boundary too. A class in your plugin that `extends`
a class in the referenced tree — `WP_List_Table`, when core is referenced —
resolves its inherited methods to the parent's real body: helpers it returns
are accounted for, and taint coming back through one still lands as a finding
in your code.

## Reference a parent directory safely

A target may sit inside a referenced tree. Files already in the target set stay
in the target set.

```bash
wp-taint scan $WPC/plugins/client-shared --include-path=$WPC/plugins
```

`client-shared` is still reported on. Every other plugin under `plugins/`
supplies symbols only. You do not need to list them individually or exclude your
own plugin from the reference.

> **Warning**
> Reference selectively. A full `wp-content/plugins` on a real install is tens
> of thousands of files. On a measured client site, three referenced plugins
> took a 50-second scan to 7 minutes 36 seconds. Reference the plugins your code
> actually calls into, and nothing else.

## Define what the scan cannot see with a bootstrap file

Some constants live outside anything you would scan — `ABSPATH` is defined in
`wp-config.php`. A bootstrap file names them, the way PHPStan's does:

```php
<?php
// wp-taint-bootstrap.php
define( 'ABSPATH', '/var/www/site/' );
```

```toml
[scan]
bootstrap = ["wp-taint-bootstrap.php"]
```

The file is parsed for what it defines and never reported on. Any include built
from those constants then resolves, provided the file it points at is in the
scan or a referenced tree.

## Do not reference WordPress core

Measured on a client theme: 310 files scan in 1.8 seconds alone and 163 seconds
with `wp-includes` referenced, and the ten extra findings were all false
positives from core's block-template machinery.

The catalogue already models the core functions that matter. Referencing core
adds cost and noise, not accuracy.

## Save the command as a config file

Put `wp-taint.toml` at the root the paths are relative to, usually
`wp-content/`. wp-taint finds it by walking up from the working directory.

```toml
[scan]
paths     = ["themes/client-org-theme", "themes/client-news-theme", "plugins/client-shared"]
reference = ["plugins/co-authors-plus", "client-mu-plugins"]
exclude   = ["*/vendor/*", "*/node_modules/*", "*/dist/*"]

[scan.options]
jobs    = 4
fail_on = "high"
```

Then run it with no arguments:

```bash
wp-taint scan
```

Anything given on the command line wins. Paths given as arguments **replace** the
configured ones rather than adding to them, so `wp-taint scan ./themes/one`
scans exactly that.

## Verify it worked

Check that the file count matches what you expect and that findings land only in
your own directories:

```bash
wp-taint scan --format=json -o findings.json
```

```bash
python3 -c "
import json, collections
f = json.load(open('findings.json'))['findings']
print(collections.Counter(x['location']['file'].split('/')[0] for x in f))"
```

Every key in that output should be a directory you wrote, or a filename if you
scanned a single directory. If a referenced tree appears, it is in the targets
list by mistake.

## Speed it up

- `--jobs=4` runs the fixed point across worker processes. Needs `ext-pcntl`.
- `--exclude='*/vendor/*'` and `--exclude='*/node_modules/*'` skip trees that
  are never your code. Build output such as `*/dist/*` is often a duplicate of
  `*/src/*` and doubles both time and findings.
- Reference fewer trees. It is almost always the dominant cost.

## Related

- [Getting started](getting-started.md) for your first scan
- [CLI reference](cli-reference.md) for every option
- [Troubleshooting](troubleshooting.md) if a scan looks stuck or reports too much
