<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Report;

use Enshrined\WpTaint\Finding\Severity;

/**
 * Terminal colour, with `NO_COLOR` and non-TTY both honoured.
 */
final class Ansi
{
    public function __construct(private readonly bool $enabled)
    {
    }

    public static function detect(mixed $stream = null): self
    {
        if (getenv('NO_COLOR') !== false) {
            return new self(false);
        }

        if (getenv('FORCE_COLOR') !== false) {
            return new self(true);
        }

        $stream ??= defined('STDOUT') ? STDOUT : null;

        if (! is_resource($stream)) {
            return new self(false);
        }

        return new self(function_exists('posix_isatty') && @posix_isatty($stream));
    }

    public function wrap(string $text, string $code): string
    {
        return $this->enabled ? "\033[" . $code . 'm' . $text . "\033[0m" : $text;
    }

    public function severity(Severity $severity, string $text): string
    {
        return $this->wrap($text, match ($severity) {
            Severity::Critical => '1;31',
            Severity::High => '31',
            Severity::Medium => '33',
            Severity::Low, Severity::Notice => '2',
        });
    }

    public function bold(string $text): string
    {
        return $this->wrap($text, '1');
    }

    public function dim(string $text): string
    {
        return $this->wrap($text, '2');
    }

    public function red(string $text): string
    {
        return $this->wrap($text, '31');
    }

    public function cyan(string $text): string
    {
        return $this->wrap($text, '36');
    }

    public function green(string $text): string
    {
        return $this->wrap($text, '32');
    }
}
