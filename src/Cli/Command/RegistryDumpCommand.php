<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Cli\Application;
use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\InputReader;
use Enshrined\WpTaint\Registry\Propagator;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Registry\SafeCall;
use Enshrined\WpTaint\Registry\Sanitizer;
use Enshrined\WpTaint\Registry\Sink;
use Enshrined\WpTaint\Registry\Source;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * Prints the fully resolved catalogue so a human can audit it against WPCS.
 *
 * The catalogue is the expensive, already-curated asset this tool is built
 * around. Being able to read it in one place, after inheritance and overrides
 * have been applied, is what makes it reviewable.
 */
#[AsCommand(name: 'registry:dump', description: 'Print the fully resolved sources, sinks and sanitizers')]
final class RegistryDumpCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('registry', null, InputOption::VALUE_REQUIRED, 'Registry name or path', 'wordpress')
            ->addOption('config', null, InputOption::VALUE_REQUIRED, 'Project config file to layer on top')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'text or json', 'text');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $reader = new InputReader($input);

        try {
            $registry = (new RegistryLoader(Application::registryDirectory()))->load(
                $reader->string('registry', 'wordpress'),
                $reader->nullableString('config'),
            );
        } catch (Throwable $error) {
            $output->writeln('<error>' . $error->getMessage() . '</error>');

            return ExitCode::ERROR;
        }

        if ($reader->string('format', 'text') === 'json') {
            $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

            $output->write(json_encode($this->toArray($registry), $flags) . "\n", false, OutputInterface::OUTPUT_RAW);

            return ExitCode::CLEAN;
        }

        $this->renderText($registry, $output);

        return ExitCode::CLEAN;
    }

    private function renderText(Registry $registry, OutputInterface $output): void
    {
        $output->writeln(sprintf('<info>Registry chain:</info> %s', implode(' → ', $registry->names)));
        $output->writeln('');

        $this->section($output, sprintf('SOURCES (%d)', count($registry->sources())));

        foreach ($registry->sources() as $source) {
            $output->writeln(sprintf(
                '  %-44s %s%s',
                $source->matcher->describe(),
                $source->kinds->describe(),
                $source->stored ? '  [stored]' : '',
            ));

            $this->note($output, $source->note);
            $this->keys($output, $source);
        }

        $this->section($output, sprintf('SANITIZERS (%d)', count($registry->sanitizers())));

        foreach ($registry->sanitizers() as $sanitizer) {
            $output->writeln(sprintf(
                '  %-44s clears %s  args %s%s%s',
                $sanitizer->matcher->describe(),
                $sanitizer->describeClears(),
                $sanitizer->arguments->describe(),
                $sanitizer->requiresLiteralArgument !== null
                    ? sprintf('  [requires literal arg %d]', $sanitizer->requiresLiteralArgument)
                    : '',
                $sanitizer->imprecise ? '  [imprecise]' : '',
            ));

            $this->note($output, $sanitizer->note);
        }

        $this->section(
            $output,
            sprintf('PROPAGATORS (%d) — these are NOT sanitizers', count($registry->propagators())),
        );

        foreach ($registry->propagators() as $propagator) {
            $output->writeln(sprintf(
                '  %-44s args %s',
                $propagator->matcher->describe(),
                $propagator->arguments->describe(),
            ));

            $this->note($output, $propagator->note);
        }

        $sinks = $registry->sinks() === [] ? [] : array_merge(...array_values($registry->sinks()));

        $this->section($output, sprintf('SINKS (%d)', count($sinks)));

        foreach ($sinks as $sink) {
            $output->writeln(sprintf(
                '  %-44s %-12s %-8s args %s  %s%s',
                $sink->matcher->describe(),
                $sink->kind->value,
                $sink->severity->value,
                $sink->arguments->describe(),
                $sink->ruleId,
                $this->sinkFlag($sink),
            ));

            $this->note($output, $sink->note);
        }

        $this->section(
            $output,
            sprintf('EXPLICITLY SAFE (%d) — never re-add these as sinks', count($registry->safeCalls())),
        );

        foreach ($registry->safeCalls() as $safe) {
            $output->writeln(sprintf('  %-44s %s', $safe->matcher->describe(), $safe->note));
        }

        $this->section($output, sprintf('RULES (%d)', count($registry->rules())));

        foreach ($registry->rules() as $rule) {
            $output->writeln(sprintf('  %-44s %s', $rule->id, $rule->title));
        }

        $this->section($output, 'SAFE DATABASE IDENTIFIERS');
        $output->writeln('  ' . wordwrap(implode(', ', $registry->safeDatabaseIdentifiers()), 100, "\n  "));
    }

    private function section(OutputInterface $output, string $title): void
    {
        $output->writeln('');
        $output->writeln('<comment>' . $title . '</comment>');
        $output->writeln(str_repeat('─', min(100, max(20, strlen($title)))));
    }

    private function note(OutputInterface $output, ?string $note): void
    {
        if ($note === null) {
            return;
        }

        $output->writeln('      ' . wordwrap($note, 92, "\n      "));
    }

    private function keys(OutputInterface $output, Source $source): void
    {
        if ($source->keys === null && $source->keyPrefixes === []) {
            return;
        }

        $parts = [];

        if ($source->keys !== null) {
            $parts[] = 'keys: ' . implode(', ', $source->keys);
        }

        if ($source->keyPrefixes !== []) {
            $parts[] = 'prefixes: ' . implode(', ', $source->keyPrefixes);
        }

        $output->writeln('      ' . implode('  ', $parts));
    }

    /**
     * @return array<string, mixed>
     */
    private function toArray(Registry $registry): array
    {
        return [
            'registries' => $registry->names,
            'sources' => array_map(static fn (Source $s): array => [
                'match' => $s->matcher->describe(),
                'kinds' => $s->kinds->toStrings(),
                'stored' => $s->stored,
                'keys' => $s->keys,
                'keyPrefixes' => $s->keyPrefixes,
                'note' => $s->note,
            ], $registry->sources()),
            'sanitizers' => array_map(static fn (Sanitizer $s): array => [
                'match' => $s->matcher->describe(),
                'clears' => $s->describeClears(),
                'args' => $s->arguments->describe(),
                'requiresLiteralArg' => $s->requiresLiteralArgument,
                'imprecise' => $s->imprecise,
                'note' => $s->note,
            ], $registry->sanitizers()),
            'propagators' => array_map(static fn (Propagator $p): array => [
                'match' => $p->matcher->describe(),
                'args' => $p->arguments->describe(),
                'note' => $p->note,
            ], $registry->propagators()),
            'sinks' => array_map(static fn (Sink $s): array => [
                'match' => $s->matcher->describe(),
                'kind' => $s->kind->value,
                'severity' => $s->severity->value,
                'args' => $s->arguments->describe(),
                'ruleId' => $s->ruleId,
                'storedWrite' => $s->storedWrite,
                'appliesBy' => $s->appliesBy,
                'note' => $s->note,
            ], $registry->sinks() === [] ? [] : array_merge(...array_values($registry->sinks()))),
            'safe' => array_map(static fn (SafeCall $s): array => [
                'match' => $s->matcher->describe(),
                'note' => $s->note,
            ], $registry->safeCalls()),
            'rules' => array_map(static fn (object $r): array => [
                'id' => $r->id,
                'title' => $r->title,
                'description' => $r->description,
                'remediation' => $r->remediation,
                'cwe' => $r->cwe,
            ], $registry->rules()),
            'safeDatabaseIdentifiers' => $registry->safeDatabaseIdentifiers(),
        ];
    }

    private function sinkFlag(Sink $sink): string
    {
        if ($sink->storedWrite) {
            return '  [stored write]';
        }

        return $sink->appliesBy === null ? '' : '  [' . $sink->appliesBy . ']';
    }
}
