<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

use InvalidArgumentException;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function rank(): int
    {
        return match ($this) {
            self::Low => 0,
            self::Medium => 1,
            self::High => 2,
            self::Critical => 3,
        };
    }

    public function atLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /**
     * SARIF has no `critical`. Both critical and high map to `error`; the real
     * severity travels in `properties.problemSeverity`.
     */
    public function sarifLevel(): string
    {
        return match ($this) {
            self::Critical, self::High => 'error',
            self::Medium => 'warning',
            self::Low => 'note',
        };
    }

    /**
     * The 0.0-10.0 numeric most SARIF viewers sort on.
     */
    public function securitySeverity(): string
    {
        return match ($this) {
            self::Critical => '9.0',
            self::High => '7.0',
            self::Medium => '5.0',
            self::Low => '3.0',
        };
    }

    public static function fromString(string $value): self
    {
        $severity = self::tryFrom($value);

        if ($severity === null) {
            throw new InvalidArgumentException(sprintf(
                'Unknown severity "%s". Expected one of: low, medium, high, critical.',
                $value,
            ));
        }

        return $severity;
    }
}
