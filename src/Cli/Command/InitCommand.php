<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli\Command;

use Enshrined\WpTaint\Cli\ExitCode;
use Enshrined\WpTaint\Cli\ProjectLayout;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function Laravel\Prompts\multiselect;

/**
 * Write a `wp-taint.toml` for a WordPress project.
 *
 * The command-line for a real project is six lines — three targets, two
 * references, a bootstrap — and hand-writing it was the first thing every setup
 * this tool has seen. `init` detects the themes and plugins under a
 * wp-content-shaped root, asks which are first-party, and writes the config with
 * sensible excludes and a bootstrap stub.
 */
#[AsCommand(name: 'init', description: 'Detect a WordPress project and write a wp-taint.toml')]
final class InitCommand extends Command
{
    /**
     * @param (\Closure(InputInterface): bool)|null $promptGate whether a terminal
     *        is present to prompt on; the real stream check when null. Injected
     *        so a test can force the interactive branch and drive the multiselect
     *        with a fake, without a real TTY.
     */
    public function __construct(private readonly ?\Closure $promptGate = null)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'root',
                null,
                'The wp-content directory, or a project holding one (default: current directory)',
            )
            ->addOption(
                'all',
                null,
                InputOption::VALUE_NONE,
                'Treat every detected directory as first-party, no prompt',
            )
            ->addOption('force', null, InputOption::VALUE_NONE, 'Overwrite an existing wp-taint.toml');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $rootArgument = $input->getArgument('root');
        $cwd = getcwd();
        $root = is_string($rootArgument) && $rootArgument !== ''
            ? $rootArgument
            : ($cwd === false ? '.' : $cwd);

        $target = rtrim($root, '/') . '/wp-taint.toml';

        if (is_file($target) && $input->getOption('force') !== true) {
            $output->writeln(sprintf('<error>%s already exists. Pass --force to overwrite.</error>', $target));

            return ExitCode::ERROR;
        }

        $layout = ProjectLayout::discover($root);

        if ($layout->isEmpty()) {
            $output->writeln(
                '<error>No themes or plugins found. Point init at a wp-content directory, or a project that '
                    . 'holds one.</error>',
            );

            return ExitCode::ERROR;
        }

        $candidates = $layout->all();

        // A scan targets the few directories you wrote, not the hundred you
        // didn't — picking is the whole point of the tool, so a blind --all
        // that scans everything is the trap it exists to avoid. Interactive
        // asks. Non-interactive writes a template with every candidate
        // commented out for you to uncomment, rather than guessing.
        if ($this->canPrompt($input) && $input->getOption('all') !== true) {
            $targets = $this->askWhichAreYours($candidates);

            if ($targets === []) {
                $output->writeln('<comment>Nothing selected; no config written.</comment>');

                return ExitCode::CLEAN;
            }

            $reference = array_values(array_diff($candidates, $targets));
            file_put_contents($target, self::render($targets, $reference));
            $output->writeln(sprintf(
                '<info>Wrote %s with %d director%s to scan.</info>',
                $target,
                count($targets),
                count($targets) === 1 ? 'y' : 'ies',
            ));
            $output->writeln('  Run <info>wp-taint scan</info> from here.');

            return ExitCode::CLEAN;
        }

        if ($input->getOption('all') === true) {
            file_put_contents($target, self::render($candidates, []));
            $output->writeln(sprintf('<info>Wrote %s with all %d directories.</info>', $target, count($candidates)));
            $output->writeln('  <comment>That scans everything — trim [scan] paths to what you wrote.</comment>');

            return ExitCode::CLEAN;
        }

        file_put_contents($target, self::renderTemplate($candidates));
        $output->writeln(sprintf('<info>Wrote %s as a template.</info>', $target));
        $output->writeln(sprintf(
            '  %d director%s detected and commented out under [scan] paths. Uncomment the ones you wrote.',
            count($candidates),
            count($candidates) === 1 ? 'y' : 'ies',
        ));

        return ExitCode::CLEAN;
    }

    /**
     * Whether there is a terminal to prompt on.
     *
     * Two gates, and both matter. Symfony's isInteractive() is driven by
     * --no-interaction, not by the pipe, and a prompt library reading a stream
     * that is not a terminal either hangs or throws, so a scan in CI without
     * the flag would break. Checking the stream too keeps the template path,
     * not a hang, the default when there is no one to answer. The decision is
     * injectable through the constructor so a test can force the interactive
     * branch and drive the prompt with a fake.
     */
    private function canPrompt(InputInterface $input): bool
    {
        if ($this->promptGate !== null) {
            return ($this->promptGate)($input);
        }

        return $input->isInteractive()
            && \defined('STDIN')
            && \function_exists('stream_isatty')
            && stream_isatty(\STDIN);
    }

    /**
     * The multiselect a real terminal gets: space to check, enter to confirm.
     *
     * Nothing is pre-selected, because the question is which of the detected
     * directories you wrote, and the tool cannot know. What is left unchecked
     * becomes the reference set: analysed for symbols, never reported on. An
     * empty selection is allowed and handled by the caller.
     *
     * @param list<string> $candidates
     *
     * @return list<string>
     */
    private function askWhichAreYours(array $candidates): array
    {
        $selected = multiselect(
            label: 'Which of these directories did you write?',
            options: $candidates,
            scroll: 15,
            hint: 'Space to select, Enter to confirm. Everything left unchecked becomes reference-only.',
        );

        return array_values(array_map(static fn (mixed $value): string => (string) $value, $selected));
    }

    /**
     * @param list<string> $targets
     * @param list<string> $reference
     */
    private static function render(array $targets, array $reference): string
    {
        $lines = ['[scan]', 'paths = ' . self::toml($targets)];

        if ($reference !== []) {
            $lines[] = '# Analysed for symbols so cross-references resolve, never reported on.';
            $lines[] = 'reference = ' . self::toml($reference);
        }

        $lines[] = '# A file defining constants the scan cannot otherwise see, e.g. ABSPATH.';
        $lines[] = '# Create it and uncomment, or delete this line.';
        $lines[] = '# bootstrap = ["wp-taint-bootstrap.php"]';
        $lines[] = 'exclude = ["*/vendor/*", "*/node_modules/*", "*/dist/*", "*/build/*", "*/tests/*"]';
        $lines[] = '';
        $lines[] = '[scan.options]';
        $lines[] = 'jobs = 4';
        $lines[] = 'fail_on = "high"';
        $lines[] = '';

        return implode("\n", $lines);
    }

    /**
     * A config with nothing selected: every candidate is a commented
     * suggestion under an empty `paths`, for the developer to uncomment.
     *
     * @param list<string> $candidates
     */
    private static function renderTemplate(array $candidates): string
    {
        $lines = [
            '[scan]',
            '# Uncomment the directories you wrote. Everything else can go under',
            '# reference = [...] so its symbols resolve without being reported on.',
            'paths = [',
        ];

        foreach ($candidates as $candidate) {
            $lines[] = '  # "' . $candidate . '",';
        }

        $lines[] = ']';
        $lines[] = '# bootstrap = ["wp-taint-bootstrap.php"]  # constants the scan cannot see, e.g. ABSPATH';
        $lines[] = 'exclude = ["*/vendor/*", "*/node_modules/*", "*/dist/*", "*/build/*", "*/tests/*"]';
        $lines[] = '';
        $lines[] = '[scan.options]';
        $lines[] = 'jobs = 4';
        $lines[] = 'fail_on = "high"';
        $lines[] = '';

        return implode("\n", $lines);
    }

    /**
     * @param list<string> $values
     */
    private static function toml(array $values): string
    {
        return '[' . implode(', ', array_map(static fn (string $value): string => '"' . $value . '"', $values)) . ']';
    }
}
