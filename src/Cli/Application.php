<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Cli\Command\DumpCfgCommand;
use Enshrined\WpTaint\Cli\Command\ExplainCommand;
use Enshrined\WpTaint\Cli\Command\InitCommand;
use Enshrined\WpTaint\Cli\Command\RegistryDumpCommand;
use Enshrined\WpTaint\Cli\Command\ScanCommand;
use Symfony\Component\Console\Application as ConsoleApplication;

final class Application extends ConsoleApplication
{
    public const VERSION = '0.1.0';

    public function __construct()
    {
        parent::__construct('wp-taint', self::VERSION);

        // `addCommand()` where it exists (console 7.4+), `add()` below it.
        // 7.4 deprecated add() in favour of addCommand(), but this package
        // supports ^7.0 and addCommand() does not exist there, so a bare call
        // to either one is wrong on half the supported range. The runtime
        // check honours both: no deprecation on new Symfony, no fatal on old.
        $commands = [
            new ScanCommand(),
            new DumpCfgCommand(),
            new RegistryDumpCommand(),
            new ExplainCommand(),
            new InitCommand(),
        ];

        foreach ($commands as $command) {
            method_exists($this, 'addCommand') ? $this->addCommand($command) : $this->add($command);
        }

        $this->setDefaultCommand('scan');
    }

    /**
     * The directory holding the bundled registries.
     *
     * Resolved relative to this file so it works both from a checkout and from
     * inside a consumer's `vendor/`.
     */
    public static function registryDirectory(): string
    {
        return dirname(__DIR__, 2) . '/registries';
    }
}
