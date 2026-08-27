<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

final class UnresolvedHook
{
    public function __construct(
        public readonly string $hook,
        public readonly string $file,
        public readonly int $line,
        public readonly string $reason,
    ) {
    }

    public function describe(): string
    {
        return sprintf('%s:%d  %s — %s', $this->file, $this->line, $this->hook, $this->reason);
    }
}
