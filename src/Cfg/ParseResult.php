<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use LogicException;

/**
 * Either a {@see ParsedFile} or a {@see ParseError}. Never null, never an empty
 * script.
 */
final class ParseResult
{
    private function __construct(
        private readonly ?ParsedFile $file,
        private readonly ?ParseError $error,
    ) {
    }

    public static function success(ParsedFile $file): self
    {
        return new self($file, null);
    }

    public static function failure(ParseError $error): self
    {
        return new self(null, $error);
    }

    public function isSuccess(): bool
    {
        return $this->file !== null;
    }

    public function file(): ParsedFile
    {
        if ($this->file === null) {
            throw new LogicException('ParseResult::file() called on a failed parse. Check isSuccess() first.');
        }

        return $this->file;
    }

    public function error(): ParseError
    {
        if ($this->error === null) {
            throw new LogicException('ParseResult::error() called on a successful parse. Check isSuccess() first.');
        }

        return $this->error;
    }
}
