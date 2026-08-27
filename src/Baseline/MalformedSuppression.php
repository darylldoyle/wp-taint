<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Baseline;

final class MalformedSuppression
{
    public function __construct(
        public readonly string $file,
        public readonly int $line,
        public readonly string $ruleId,
        public readonly string $reason,
    ) {
    }

    public function describe(): string
    {
        return sprintf(
            '%s:%d  wp-taint-ignore-next-line %s — %s',
            $this->file,
            $this->line,
            $this->ruleId,
            $this->reason,
        );
    }
}
