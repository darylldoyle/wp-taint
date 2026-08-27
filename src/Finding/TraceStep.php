<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

use Enshrined\WpTaint\Taint\TaintSet;

/**
 * One step on the path from source to sink.
 *
 * The trace is not optional. A finding that says "tainted" without showing how
 * the value got there is a finding nobody acts on.
 */
final class TraceStep
{
    /**
     * @param int|null $endColumn Null when the operand's span is unknown; the
     *                            reporters omit the caret line rather than
     *                            guessing at it.
     */
    public function __construct(
        public readonly TraceVerb $verb,
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly ?int $endColumn,
        public readonly string $snippet,
        public readonly string $description,
        public readonly TaintSet $kinds,
        public readonly ?string $callee = null,
        public readonly ?int $parameterIndex = null,
    ) {
    }

    public function withDescription(string $description): self
    {
        return new self(
            $this->verb,
            $this->file,
            $this->line,
            $this->column,
            $this->endColumn,
            $this->snippet,
            $description,
            $this->kinds,
            $this->callee,
            $this->parameterIndex,
        );
    }
}
