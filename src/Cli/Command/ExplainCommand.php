<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ConstantTableBuilder;
use Enshrined\WpTaint\Cfg\IncludeGraphBuilder;
use Enshrined\WpTaint\Cfg\IncludeResolver;
use Enshrined\WpTaint\Cli\Application;
use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\InputReader;
use Enshrined\WpTaint\Hooks\HookGraphBuilder;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\CallableResolver;
use Enshrined\WpTaint\Taint\CallResolver;
use Enshrined\WpTaint\Taint\Explainer;
use Enshrined\WpTaint\Taint\InterproceduralResolver;
use Enshrined\WpTaint\Taint\IntraproceduralAnalyzer;
use Enshrined\WpTaint\Taint\ReceiverResolver;
use Enshrined\WpTaint\Taint\SummaryExtractor;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\UserFunctionTable;
use Enshrined\WpTaint\Taint\ValueResolver;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * `wp-taint explain path/to/file.php:58 --kind=html`
 *
 * The false-negative debugger. Arguably more valuable than any report format,
 * because the failure mode this tool most needs to defend against is silence.
 */
#[AsCommand(name: 'explain', description: 'Explain the taint state at a location, and why it is what it is')]
final class ExplainCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('location', InputArgument::REQUIRED, 'file.php:LINE')
            ->addOption('kind', null, InputOption::VALUE_REQUIRED, 'The taint kind to ask about')
            ->addOption('registry', null, InputOption::VALUE_REQUIRED, 'Registry name or path', 'wordpress')
            ->addOption('scope', null, InputOption::VALUE_REQUIRED, 'Directory to analyse for cross-file flows')
            ->addOption(
                'no-follow-includes',
                null,
                InputOption::VALUE_NONE,
                'Do not join scopes across include and require',
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
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $reader = new InputReader($input);
        $location = $reader->stringArgument('location');

        if (preg_match('/^(?<file>.+):(?<line>\d+)$/', $location, $matches) !== 1) {
            $output->writeln('<error>Location must be in the form path/to/file.php:LINE</error>');

            return ExitCode::ERROR;
        }

        $file = $matches['file'];
        $line = (int) $matches['line'];

        if (! is_file($file)) {
            $output->writeln(sprintf('<error>File not found: %s</error>', $file));

            return ExitCode::ERROR;
        }

        $kindOption = $reader->nullableString('kind');
        $kind = null;

        if ($kindOption !== null) {
            $kind = TaintKind::tryFrom($kindOption);

            if ($kind === null || ! $kind->isDataflowKind()) {
                $output->writeln(sprintf('<error>Unknown taint kind "%s".</error>', $kindOption));

                return ExitCode::ERROR;
            }
        }

        $scope = $reader->nullableString('scope') ?? dirname($file);
        $root = PathHelper::normalise($scope);

        try {
            $registry = (new RegistryLoader(Application::registryDirectory()))
                ->load($reader->string('registry', 'wordpress'))
                ->configured(true, false);
        } catch (Throwable $error) {
            $output->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        $options = new AnalysisOptions(
            dynamicCalls: $reader->dynamicCallPolicy(),
            followIncludes: ! $reader->bool('no-follow-includes'),
        );

        $builder = new CfgBuilder($root);
        $functions = new UserFunctionTable();
        $target = null;

        foreach ((new FileFinder())->find([$scope]) as $candidate) {
            $result = $builder->buildFromFile($candidate);

            if (! $result->isSuccess()) {
                if (PathHelper::normalise($candidate) === PathHelper::normalise($file)) {
                    $error = $result->error();
                    $output->writeln(sprintf('<error>%s:%d  %s</error>', $error->file, $error->line, $error->message));

                    return ExitCode::ERROR;
                }

                continue;
            }

            $parsed = $result->file();
            $functions->addFile($parsed);

            if (PathHelper::normalise($candidate) === PathHelper::normalise($file)) {
                $target = $parsed;
            }
        }

        if ($target === null) {
            $output->writeln(sprintf(
                '<error>%s was not reached from the analysis scope (%s). Pass --scope explicitly.</error>',
                $file,
                $scope,
            ));

            return ExitCode::ERROR;
        }

        $contexts = $functions->all();
        $receivers = new ReceiverResolver();
        $constants = (new ConstantTableBuilder(new ValueResolver()))->build($contexts);
        $values = (new ValueResolver())->withConstants($constants);
        $callables = new CallableResolver($registry, $functions, $values);

        // The same hook graph the scan builds. Without it `explain` would say a
        // value is clean where `scan` reports a finding through a filter
        // callback, and the whole point of this command is that the two agree.
        $hooks = (new HookGraphBuilder($callables, $values, $receivers))->build($contexts);

        // Same include graph the scan builds, or `explain` would report a value
        // clean where `scan` reports a finding through a template.
        $includes = $options->followIncludes
            ? (new IncludeGraphBuilder(
                new IncludeResolver($values, (new FileFinder())->find([$scope]), $root),
                $root,
            ))->build($contexts)
            : null;

        $resolver = new CallResolver($registry, $functions, $callables, $values, $receivers, $hooks);
        $analyzer = new IntraproceduralAnalyzer($registry, $functions, $resolver, $options, $includes);
        $extractor = new SummaryExtractor($analyzer, $options);
        $resolution = (new InterproceduralResolver($analyzer, $extractor, $options))->resolve($contexts);

        $explanation = (new Explainer($registry, $resolver, $analyzer, $options))->explain(
            $target,
            $line,
            $contexts,
            $resolution['summaries'],
            $resolution['properties'],
            $resolution['scopes'],
            $kind,
        );

        $output->write($explanation->render(), false, OutputInterface::OUTPUT_RAW);

        return ExitCode::CLEAN;
    }
}
