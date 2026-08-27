<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Cli\Command\DumpCfgCommand;
use Enshrined\WpTaint\Cli\Command\ExplainCommand;
use Enshrined\WpTaint\Cli\Command\RegistryDumpCommand;
use Enshrined\WpTaint\Cli\Command\ScanCommand;
use Symfony\Component\Console\Application as ConsoleApplication;

final class Application extends ConsoleApplication
{
    public const VERSION = '0.1.0';

    public function __construct()
    {
        parent::__construct('wp-taint', self::VERSION);

        $this->addCommand(new ScanCommand());
        $this->addCommand(new DumpCfgCommand());
        $this->addCommand(new RegistryDumpCommand());
        $this->addCommand(new ExplainCommand());

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
