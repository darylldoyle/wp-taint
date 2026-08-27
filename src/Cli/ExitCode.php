<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

/**
 * `2` covers any parse failure as well as an execution error.
 *
 * That is deliberate and it is the point of the whole "fail loudly" rule: a
 * file the scanner could not read is a file it could not clear, and a green
 * build over an unread file is a lie.
 */
final class ExitCode
{
    public const CLEAN = 0;

    public const FINDINGS = 1;

    public const ERROR = 2;
}
