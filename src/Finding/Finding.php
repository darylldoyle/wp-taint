<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

use Enshrined\WpTaint\Taint\TaintKind;

final class Finding
{
    /**
     * @param list<TraceStep> $trace source to sink, in order
     */
    public function __construct(
        public readonly string $ruleId,
        public readonly RuleDefinition $rule,
        public readonly Severity $severity,
        public readonly TaintKind $kind,
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly ?int $endColumn,
        public readonly string $message,
        public readonly array $trace,
        public readonly string $fingerprint,
        public readonly bool $imprecise = false,
    ) {
    }

    /**
     * Deterministic ordering: file, line, column, rule id.
     *
     * Byte-identical output across runs is a hard requirement, and PHP's sort
     * is not stable for equal keys, so the comparison has to be total.
     */
    public function compareTo(self $other): int
    {
        return [$this->file, $this->line, $this->column, $this->ruleId, $this->fingerprint]
            <=> [$other->file, $other->line, $other->column, $other->ruleId, $other->fingerprint];
    }

    /**
     * @param list<TraceStep> $trace
     */
    public function withTrace(array $trace): self
    {
        return new self(
            $this->ruleId,
            $this->rule,
            $this->severity,
            $this->kind,
            $this->file,
            $this->line,
            $this->column,
            $this->endColumn,
            $this->message,
            $trace,
            $this->fingerprint,
            $this->imprecise,
        );
    }
}
