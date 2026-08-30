# wp-taint documentation

## Start here

| Document | For |
|----------|-----|
| [Getting started](getting-started.md) | Install, first scan, reading a finding |
| [Scan your own code inside a WordPress install](scanning-a-wordpress-project.md) | Reporting on a few directories among thousands of files |
| [Troubleshooting](troubleshooting.md) | A scan that looks stuck, wrong or too loud |
| [Running in CI](ci.md) | A GitHub Actions job with baseline and SARIF |

## Reference

| Document | Contains |
|----------|----------|
| [CLI reference](cli-reference.md) | Every command, option, config key, exit code and rule id |
| [Known limitations](../KNOWN_LIMITATIONS.md) | What the engine does at the edges, and why |
| [Changelog](../CHANGELOG.md) | What changed between versions |

## Understanding it

| Document | Explains |
|----------|----------|
| [How it works](how-it-works.md) | Sources, sinks, taint kinds, and the decisions behind them |
| [Benchmark](benchmark.md) | Scored against Semgrep and Psalm on a shared suite |
| [Tuning log](tuning.md) | Every false positive class found on real plugins, and what fixed it |

## Contributing

| Document | Contains |
|----------|----------|
| [php-cfg API notes](php-cfg-api-notes.md) | The CFG library's shape, for engine work |
| [Name resolution](resolution.md) | Which of the five resolvers answers what, and why |
