<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * A file that could not be turned into a CFG.
 *
 * This is a reported error, never a skipped file. A security scanner that
 * silently ignores what it cannot read produces silent false negatives, which
 * is the worst failure mode available to it.
 */
final class ParseError
{
    public function __construct(
        public readonly string $file,
        public readonly int $line,
        public readonly string $message,
    ) {
    }

    /**
     * @return array{file: string, line: int, message: string}
     */
    public function toArray(): array
    {
        return [
            'file' => $this->file,
            'line' => $this->line,
            'message' => $this->message,
        ];
    }
}
