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

        // `add()` and not `addCommand()`, despite the deprecation notice on
        // console 7.4. addCommand() arrived in 7.4 and this package supports
        // ^7.0, so calling it breaks every consumer below that — the lowest-deps
        // CI job failed exactly this way. Narrowing the constraint to ^7.4 to
        // silence a notice would push that cost onto everyone installing this
        // alongside an older Symfony, which is a worse trade than the notice.
        $this->add(new ScanCommand());
        $this->add(new DumpCfgCommand());
        $this->add(new RegistryDumpCommand());
        $this->add(new ExplainCommand());

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
