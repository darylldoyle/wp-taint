<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\Severity;

/**
 * A sink reachable from a function parameter, recorded on that function's
 * summary so a caller can report it without re-analysing the callee.
 *
 * Deliberately plain data — scalars, enums and a TaintKind. Summaries cross
 * process boundaries under `--jobs`, so nothing here may hold a php-cfg object.
 * Everything a caller needs to render the finding is already captured at
 * extraction time.
 */
final class SinkReference
{
    public function __construct(
        public readonly string $ruleId,
        public readonly TaintKind $kind,
        public readonly Severity $severity,
        public readonly string $sinkIdentity,
        public readonly string $file,
        public readonly string $relativeFile,
        public readonly int $line,
        public readonly int $column,
        public readonly ?int $endColumn,
        public readonly string $snippet,
        public readonly string $functionDisplayName,
        public readonly bool $imprecise = false,
    ) {
    }

    public function identityKey(): string
    {
        return implode('|', [$this->ruleId, $this->relativeFile, (string) $this->line, (string) $this->column]);
    }
}
