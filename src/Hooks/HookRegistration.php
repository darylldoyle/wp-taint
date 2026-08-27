<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\CallTarget;

/**
 * One `add_action()` or `add_filter()` call, resolved.
 *
 * The callback is stored as a {@see CallTarget} because that is exactly what a
 * hook dispatch needs to become: a call edge like any other. Priority is
 * recorded for the trace text only — a union does not care what order its
 * members arrive in.
 */
final class HookRegistration
{
    public function __construct(
        public readonly string $hook,
        public readonly CallTarget $callback,
        public readonly string $file,
        public readonly int $line,
        public readonly int $priority = 10,
        public readonly int $acceptedArgs = 1,
    ) {
    }

    /**
     * Registrations are merged from every worker and every file, so the order
     * they were discovered in must not survive into the output.
     */
    public function sortKey(): string
    {
        return implode("\0", [
            $this->hook,
            sprintf('%08d', $this->priority),
            $this->callback->identity(),
            $this->file,
            sprintf('%08d', $this->line),
        ]);
    }
}
