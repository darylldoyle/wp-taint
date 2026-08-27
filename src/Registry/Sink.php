<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Taint\TaintKind;

/**
 * Somewhere tainted data becomes a vulnerability.
 */
final class Sink
{
    public function __construct(
        public readonly Matcher $matcher,
        public readonly ArgumentSelector $arguments,
        public readonly TaintKind $kind,
        public readonly Severity $severity,
        public readonly string $ruleId,
        public readonly ?string $note = null,
        /**
         * The write side of second-order taint: `update_option()` and friends.
         * Off unless `--stored-taint-writes` is passed, because on most
         * codebases these dominate the output.
         */
        public readonly bool $storedWrite = false,
    ) {
    }
}
