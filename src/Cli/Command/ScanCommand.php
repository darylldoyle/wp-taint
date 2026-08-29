<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Baseline\Baseline;
use Enshrined\WpTaint\Baseline\BaselineWriter;
use Enshrined\WpTaint\Baseline\InlineSuppressions;
use Enshrined\WpTaint\Cli\Application;
use Enshrined\WpTaint\Cli\ConsoleScanProgress;
use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\InputReader;
use Enshrined\WpTaint\Cli\ProjectScanConfig;
use Enshrined\WpTaint\Cli\ScanConfiguration;
use Enshrined\WpTaint\Report\Ansi;
use Enshrined\WpTaint\Report\ConsoleReporter;
use Enshrined\WpTaint\Report\JsonReporter;
use Enshrined\WpTaint\Report\Reporter;
use Enshrined\WpTaint\Report\ReportOptions;
use Enshrined\WpTaint\Report\SarifReporter;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\NullScanProgress;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Scan\ScanRunner;
use Enshrined\WpTaint\Support\PathHelper;
use InvalidArgumentException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

#[AsCommand(name: 'scan', description: 'Find XSS, SQL injection and authorization bugs in WordPress PHP')]
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument(
                'paths',
                InputArgument::IS_ARRAY,
                'Files or directories to scan (default: [scan] paths in wp-taint.toml)',
            )
            ->addOption(
                'registry',
                null,
                InputOption::VALUE_REQUIRED,
                'Registry name or path to a TOML file',
                'wordpress',
            )
            ->addOption(
                'config',
                null,
                InputOption::VALUE_REQUIRED,
                'Project config file (defaults to ./wp-taint.toml if present)',
            )
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'console, json or sarif', 'console')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Write the report to a file instead of stdout')
            ->addOption('baseline', null, InputOption::VALUE_REQUIRED, 'Suppress findings listed in this baseline file')
            ->addOption(
                'generate-baseline',
                null,
                InputOption::VALUE_OPTIONAL,
                'Write current findings to a baseline file',
                false,
            )
            ->addOption('min-severity', null, InputOption::VALUE_REQUIRED, 'low, medium, high or critical', 'low')
            ->addOption(
                'fail-on',
                null,
                InputOption::VALUE_REQUIRED,
                'Exit 1 at or above this severity, or "never"',
                'high',
            )
            ->addOption(
                'no-interprocedural',
                null,
                InputOption::VALUE_NONE,
                'Do not follow taint across function boundaries',
            )
            ->addOption(
                'no-stored-taint',
                null,
                InputOption::VALUE_NONE,
                'Do not treat options and post meta as tainted',
            )
            ->addOption(
                'stored-taint-writes',
                null,
                InputOption::VALUE_NONE,
                'Report untrusted data written to options and meta',
            )
            ->addOption(
                'dynamic-calls',
                null,
                InputOption::VALUE_REQUIRED,
                'How to treat a call whose callee cannot be resolved: clean, propagate (default) or tainted',
            )
            ->addOption(
                'assume-dynamic-tainted',
                null,
                InputOption::VALUE_NONE,
                'Deprecated alias for --dynamic-calls=tainted',
            )
            ->addOption(
                'include-path',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Analyse this tree for its symbols but never report findings in it (repeatable)',
            )
            ->addOption(
                'bootstrap',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'A file whose define()s the scan should know, e.g. ABSPATH; parsed, never reported on (repeatable)',
            )
            ->addOption(
                'no-follow-includes',
                null,
                InputOption::VALUE_NONE,
                'Do not join scopes across include and require',
            )
            ->addOption(
                'unknown-provenance',
                null,
                InputOption::VALUE_NONE,
                'Deprecated: on by default. Use --no-unknown-provenance to turn it off',
            )
            ->addOption(
                'no-unknown-provenance',
                null,
                InputOption::VALUE_NONE,
                'Report only traced flows, not output whose origin cannot be established',
            )
            ->addOption('no-structural-rules', null, InputOption::VALUE_NONE, 'Run taint analysis only')
            ->addOption(
                'exclude',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Glob to exclude (repeatable)',
            )
            ->addOption('parse-report', null, InputOption::VALUE_NONE, 'List files that failed to parse, then exit')
            ->addOption(
                'dump-taint-graph',
                null,
                InputOption::VALUE_REQUIRED,
                'Write a GraphViz dot file of the taint graph',
            )
            ->addOption('trace-full', null, InputOption::VALUE_NONE, 'Never collapse the middle of a long trace')
            ->addOption('jobs', 'j', InputOption::VALUE_REQUIRED, 'Number of worker processes', '1')
            ->setHelp(<<<'HELP'
              <info>wp-taint scan ./src</info>

              Reports untrusted input reaching an output, database, filesystem, shell or
              deserialization sink, plus REST and AJAX endpoints with no authorization check.

              Exit codes:
                <comment>0</comment>  clean
                <comment>1</comment>  findings at or above --fail-on
                <comment>2</comment>  execution error, including any file that failed to parse

              To hand results to an agent, use <info>--format=json</info>. Console output is lossy by
              design; the JSON carries the full trace and is self-describing.
              HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $stderr = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $reader = new InputReader($input);

        // Created before anything slow happens. Walking the directory tree is
        // itself seconds of silence on a WordPress install, and a progress
        // object that only exists afterwards cannot report the part that felt
        // like a hang.
        $progress = $stderr->isDecorated() ? new ConsoleScanProgress($stderr) : new NullScanProgress();

        try {
            $configuration = $this->buildConfiguration($reader);
        } catch (Throwable $error) {
            $stderr->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        $progress->phase('Finding files', null);

        try {
            $files = (new FileFinder($configuration->excludes))->find($configuration->paths);
        } catch (Throwable $error) {
            $progress->finish();
            $stderr->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        if ($files === []) {
            $progress->finish();
            $stderr->writeln('<comment>No PHP files found in the given paths.</comment>');

            return ExitCode::CLEAN;
        }

        $result = (new ScanRunner($configuration))->run($files, $progress);
        $progress->finish();

        if ($configuration->parseReport) {
            return $this->renderParseReport($result, $output);
        }

        $result = $this->applySuppressions($configuration, $files, $result);

        if ($configuration->generateBaselinePath !== null) {
            $count = (new BaselineWriter())->write($configuration->generateBaselinePath, $result->findings);
            $output->writeln(sprintf(
                '<info>Wrote %d finding%s to %s</info>',
                $count,
                $count === 1 ? '' : 's',
                $configuration->generateBaselinePath,
            ));

            return $result->hasParseErrors() ? ExitCode::ERROR : ExitCode::CLEAN;
        }

        $this->emit($configuration, $result, $reader, $output);

        return $this->exitCode($configuration, $result);
    }

    private static function workingDirectory(): string
    {
        $cwd = getcwd();

        return $cwd === false ? '.' : $cwd;
    }

    /**
     * Merge the project's `[scan]` section with the command line.
     *
     * The command line always wins, and paths given as arguments *replace* the
     * configured ones rather than adding to them: naming a directory means to
     * scan that directory and nothing else.
     */
    private function buildConfiguration(InputReader $reader): ScanConfiguration
    {
        $arguments = $reader->stringArgumentList('paths');
        $configPath = $reader->nullableString('config')
            ?? ProjectScanConfig::discover($arguments[0] ?? self::workingDirectory());
        $project = $configPath === null ? ProjectScanConfig::empty() : ProjectScanConfig::load($configPath);
        $paths = $arguments !== [] ? $arguments : $project->paths;

        if ($paths === []) {
            throw new InvalidArgumentException(
                $configPath === null
                    ? 'No paths given. Pass one or more directories, or add a [scan] section to wp-taint.toml.'
                    : sprintf('No paths given, and %s has no [scan] paths.', $configPath),
            );
        }

        return ScanConfiguration::build(
            $paths,
            $reader->string('registry', 'wordpress'),
            $configPath,
            [...$reader->stringList('exclude'), ...$project->excludes],
            $reader->string('format', $project->format ?? 'console'),
            $reader->nullableString('output'),
            $reader->nullableString('baseline') ?? $project->baseline,
            $reader->optionalValue('generate-baseline', 'wp-taint-baseline.json'),
            $reader->string('min-severity', $project->minimumSeverity ?? 'low'),
            $reader->string('fail-on', $project->failOn ?? 'high'),
            ! $reader->bool('no-interprocedural'),
            ! $reader->bool('no-stored-taint'),
            $reader->bool('stored-taint-writes') || ($project->storedTaintWrites ?? false),
            $reader->dynamicCallPolicy(),
            ! $reader->bool('no-follow-includes'),
            ! $reader->bool('no-unknown-provenance'),
            [
                ...$reader->stringList('include-path'),
                ...$reader->stringList('bootstrap'),
                ...$project->reference,
                ...$project->bootstrap,
            ],
            $reader->bool('parse-report'),
            $reader->nullableString('dump-taint-graph'),
            ! $reader->bool('no-structural-rules'),
            $reader->int('jobs', $project->jobs ?? 1),
        );
    }

    /**
     * @param list<string> $files
     */
    private function applySuppressions(
        ScanConfiguration $configuration,
        array $files,
        ScanResult $result,
    ): ScanResult {
        $findings = $result->findings->withMinimumSeverity($configuration->minimumSeverity);

        $inline = new InlineSuppressions();

        foreach ($files as $file) {
            $source = is_readable($file) ? file_get_contents($file) : false;

            if ($source !== false) {
                $inline->addFile(PathHelper::relative($file, $configuration->root), $source);
            }
        }

        $inlineResult = $inline->apply($findings);
        $findings = $inlineResult['kept'];
        $baselineSuppressed = 0;

        if ($configuration->baselinePath !== null) {
            $baselineResult = Baseline::fromFile($configuration->baselinePath)->apply($findings);
            $findings = $baselineResult['kept'];
            $baselineSuppressed = $baselineResult['suppressed'];
        }

        return $result->withFindings($findings, $baselineSuppressed, $inlineResult['suppressed']);
    }

    private function emit(
        ScanConfiguration $configuration,
        ScanResult $result,
        InputReader $reader,
        OutputInterface $output,
    ): void {
        $reportOptions = new ReportOptions(
            verbose: $output->isVerbose(),
            colour: ! $reader->bool('no-ansi'),
            traceFull: $reader->bool('trace-full'),
            toolVersion: Application::VERSION,
        );

        $reporter = $this->reporter($configuration);
        $report = $reporter->render($result, $reportOptions);

        if ($configuration->output !== null) {
            file_put_contents($configuration->output, $report);
            $output->writeln(sprintf(
                '<info>Wrote %s report to %s</info>',
                $configuration->format,
                $configuration->output,
            ));

            return;
        }

        $output->write($report, false, OutputInterface::OUTPUT_RAW);
    }

    private function reporter(ScanConfiguration $configuration): Reporter
    {
        return match ($configuration->format) {
            'json' => new JsonReporter(),
            'sarif' => new SarifReporter(),
            default => new ConsoleReporter(
                $configuration->output !== null ? new Ansi(false) : Ansi::detect(),
            ),
        };
    }

    private function renderParseReport(ScanResult $result, OutputInterface $output): int
    {
        if ($result->parseErrors === []) {
            $output->writeln(sprintf(
                '<info>All %d files parsed.</info>',
                $result->filesScanned,
            ));

            return ExitCode::CLEAN;
        }

        $total = $result->filesScanned + count($result->parseErrors);

        $output->writeln(sprintf(
            '<error>%d of %d files failed to parse (%.2f%% parse rate)</error>',
            count($result->parseErrors),
            $total,
            $total > 0 ? 100 * $result->filesScanned / $total : 100.0,
        ));
        $output->writeln('');

        foreach ($result->parseErrors as $error) {
            $output->writeln(sprintf('  %s:%d  %s', $error->file, $error->line, $error->message));
        }

        return ExitCode::ERROR;
    }

    private function exitCode(ScanConfiguration $configuration, ScanResult $result): int
    {
        // A file we could not read is a file we could not clear.
        if ($result->hasParseErrors()) {
            return ExitCode::ERROR;
        }

        if ($configuration->failOn !== null && $result->findings->hasAtLeast($configuration->failOn)) {
            return ExitCode::FINDINGS;
        }

        return ExitCode::CLEAN;
    }
}
