# Running wp-taint in CI

A GitHub Actions job that fails a pull request on new high-severity findings,
starting from a baseline of what already exists.

## The idea

A codebase that has never been scanned has findings. Failing the first build on
all of them helps nobody. So the flow is:

1. **Baseline once**, committing the current findings as accepted.
2. **Fail on anything new** at or above your threshold.
3. **Upload SARIF** so findings appear inline on the pull request.

## The workflow

`.github/workflows/wp-taint.yml`:

```yaml
name: wp-taint

on:
  pull_request:

# upload-sarif needs security-events: write to post findings on the PR.
permissions:
  contents: read
  security-events: write

jobs:
  taint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3'
          extensions: pcntl        # parallel workers; findings are identical without it
          tools: composer

      - run: composer require --dev enshrined/wp-taint

      - name: Scan
        run: |
          vendor/bin/wp-taint scan \
            --baseline=wp-taint-baseline.json \
            --fail-on=high \
            --format=sarif \
            --output=wp-taint.sarif \
            --jobs=4

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wp-taint.sarif
```

`--jobs` needs the `pcntl` extension; the `setup-php` step above adds it. Without
it the scan runs on one process and finds exactly the same things.

## Creating the baseline

Once, on the branch you are protecting, from a checkout of the code:

```bash
vendor/bin/wp-taint scan --generate-baseline=wp-taint-baseline.json
git add wp-taint-baseline.json
git commit -m "Baseline wp-taint findings"
```

Everything in the baseline is silenced; anything new is reported. When you fix a
finding that was in the baseline, regenerate it so it cannot come back
unnoticed.

## Choosing the threshold

`--fail-on=high` (the default) fails on `high` and `critical`, and lets `medium`
and `low` through as advisory: they still appear in the SARIF, because
`--min-severity` defaults to `low`. That is the setting most teams want. The
`low` band is mostly the escape-on-output obligation, worth seeing but not worth
blocking a merge on.

Use `--fail-on=critical` to block only on the most severe, or
`--fail-on=medium` to hold a higher bar.

## What appears on the pull request

The SARIF upload puts each finding inline on the changed lines, with its rule,
severity and the source-to-sink trace. A reviewer sees the same thing the
console shows, in the diff.

## A project config instead of flags

If the repository has a `wp-taint.toml` (see
[Scanning a WordPress project](scanning-a-wordpress-project.md)), the scan step
is just:

```yaml
      - run: vendor/bin/wp-taint scan --baseline=wp-taint-baseline.json --format=sarif --output=wp-taint.sarif
```

The paths, references, excludes and job count all come from the config.

## Related

- [CLI reference](cli-reference.md): every option
- [Scanning a WordPress project](scanning-a-wordpress-project.md): the config file
- [Getting started](getting-started.md): `init`, baselines, suppressions
