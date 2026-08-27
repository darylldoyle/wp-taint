<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\InputReader;
use PHPCfg\Printer\GraphViz;
use PHPCfg\Printer\Text;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The SSA dump. The first thing to reach for when a finding looks wrong.
 */
#[AsCommand(name: 'dump-cfg', description: 'Print the SSA control flow graph for a file')]
final class DumpCfgCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('file', InputArgument::REQUIRED, 'The PHP file to dump')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'text or dot', 'text')
            ->addOption('show-lowering', null, InputOption::VALUE_NONE, 'List the constructs rewritten for php-cfg');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $reader = new InputReader($input);
        $file = $reader->stringArgument('file');

        if (! is_file($file)) {
            $output->writeln(sprintf('<error>File not found: %s</error>', $file));

            return ExitCode::ERROR;
        }

        $result = (new CfgBuilder(dirname($file)))->buildFromFile($file);

        if (! $result->isSuccess()) {
            $error = $result->error();
            $output->writeln(sprintf('<error>%s:%d  %s</error>', $error->file, $error->line, $error->message));

            return ExitCode::ERROR;
        }

        $parsed = $result->file();

        if ($reader->bool('show-lowering')) {
            if ($parsed->lowered === []) {
                $output->writeln('<info>Nothing was lowered; php-cfg parsed this file as written.</info>');
            } else {
                $output->writeln('<comment>Lowered for php-cfg before building the CFG:</comment>');

                foreach ($parsed->lowered as $construct => $count) {
                    $output->writeln(sprintf('  %-28s %d', $construct, $count));
                }
            }

            $output->writeln('');
        }

        $format = $reader->string('format', 'text');

        if ($format === 'dot') {
            // GraphViz::printScript() returns a Graph object, not a string,
            // despite sharing a signature with the text printer. Neither is
            // typed upstream, hence the narrowing.
            $dot = self::stringify((new GraphViz())->printScript($parsed->script));

            $output->write($dot, false, OutputInterface::OUTPUT_RAW);

            return ExitCode::CLEAN;
        }

        if ($format !== 'text') {
            $output->writeln(sprintf('<error>Unknown format "%s". Expected text or dot.</error>', $format));

            return ExitCode::ERROR;
        }

        $output->write(self::stringify((new Text())->printScript($parsed->script)), false, OutputInterface::OUTPUT_RAW);


        return ExitCode::CLEAN;
    }

    /**
     * php-cfg's printers declare no return type: the text printer returns a
     * string and the GraphViz printer returns a Graph that stringifies.
     */
    private static function stringify(mixed $printed): string
    {
        if (is_string($printed)) {
            return $printed;
        }

        if (is_object($printed) && method_exists($printed, '__toString')) {
            return (string) $printed;
        }

        return '';
    }
}
