<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Baseline\Baseline;
use Enshrined\WpTaint\Baseline\BaselineWriter;
use Enshrined\WpTaint\Baseline\InlineSuppressions;
use Enshrined\WpTaint\Cli\Application;
use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\InputReader;
use Enshrined\WpTaint\Cli\ScanConfiguration;
use Enshrined\WpTaint\Report\Ansi;
use Enshrined\WpTaint\Report\ConsoleReporter;
use Enshrined\WpTaint\Report\JsonReporter;
use Enshrined\WpTaint\Report\Reporter;
use Enshrined\WpTaint\Report\ReportOptions;
use Enshrined\WpTaint\Report\SarifReporter;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\ScanResult;
use Enshrined\WpTaint\Scan\ScanRunner;
use Enshrined\WpTaint\Support\PathHelper;
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
            ->addArgument('paths', InputArgument::IS_ARRAY | InputArgument::REQUIRED, 'Files or directories to scan')
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
                'assume-dynamic-tainted',
                null,
                InputOption::VALUE_NONE,
                'Treat unresolved dynamic calls as propagating all taint',
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
            ->addOption('no-cache', null, InputOption::VALUE_NONE, 'Ignore and do not write the analysis cache')
            ->addOption('cache-dir', null, InputOption::VALUE_REQUIRED, 'Where to keep the analysis cache')
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

        try {
            $configuration = $this->buildConfiguration($reader);
        } catch (Throwable $error) {
            $stderr->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        try {
            $files = (new FileFinder($configuration->excludes))->find($configuration->paths);
        } catch (Throwable $error) {
            $stderr->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        if ($files === []) {
            $stderr->writeln('<comment>No PHP files found in the given paths.</comment>');

            return ExitCode::CLEAN;
        }

        $result = (new ScanRunner($configuration))->run($files);

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

    private function buildConfiguration(InputReader $reader): ScanConfiguration
    {
        return ScanConfiguration::build(
            $reader->stringArgumentList('paths'),
            $reader->string('registry', 'wordpress'),
            $reader->nullableString('config'),
            $reader->stringList('exclude'),
            $reader->string('format', 'console'),
            $reader->nullableString('output'),
            $reader->nullableString('baseline'),
            $reader->optionalValue('generate-baseline', 'wp-taint-baseline.json'),
            $reader->string('min-severity', 'low'),
            $reader->string('fail-on', 'high'),
            ! $reader->bool('no-interprocedural'),
            ! $reader->bool('no-stored-taint'),
            $reader->bool('stored-taint-writes'),
            $reader->bool('assume-dynamic-tainted'),
            $reader->bool('parse-report'),
            $reader->nullableString('dump-taint-graph'),
            ! $reader->bool('no-structural-rules'),
            $reader->int('jobs', 1),
            ! $reader->bool('no-cache'),
            $reader->nullableString('cache-dir'),
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
