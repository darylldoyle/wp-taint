<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

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
        /**
         * What the value reaches: `echo`, `wpdb::query`, `register_rest_route`.
         *
         * The console header shows this rather than repeating the source line,
         * which the source/sink block below it already carries.
         */
        public readonly string $sinkIdentity = '',
        /**
         * Set when the author marked this line reviewed with a matching
         * `phpcs:ignore`. The finding is downgraded to {@see Severity::Notice}
         * and this records why. Null on everything else.
         */
        public readonly ?Acknowledgement $acknowledgement = null,
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
            $this->sinkIdentity,
            $this->acknowledgement,
        );
    }

    /**
     * The author marked this line reviewed with a matching `phpcs:ignore`, so
     * the finding drops to a notice and gains a trace step saying why. The
     * fingerprint is unchanged, so a baseline or a suppression still matches.
     */
    public function acknowledged(Acknowledgement $acknowledgement): self
    {
        // Record the severity being reduced, so the finding keeps what it was
        // downgraded from and the reporters can show it.
        $recorded = new Acknowledgement(
            $acknowledgement->sniff,
            $acknowledgement->reason,
            $this->severity,
        );

        $reason = $acknowledgement->reason === null ? '' : sprintf(' ("%s")', $acknowledgement->reason);
        $steps = $this->trace;
        $end = end($steps);
        $last = $end === false ? null : $end;

        $note = new TraceStep(
            $last === null ? TraceVerb::Sink : $last->verb,
            $this->file,
            $this->line,
            $this->column,
            $this->endColumn,
            $last === null ? '' : $last->snippet,
            sprintf(
                'Acknowledged in PHPCS with %s%s; severity reduced to notice. '
                    . '--no-phpcs-suppressions reports it at full severity.',
                $acknowledgement->sniff,
                $reason,
            ),
            $last === null ? TaintSet::empty() : $last->kinds,
        );

        return new self(
            $this->ruleId,
            $this->rule,
            Severity::Notice,
            $this->kind,
            $this->file,
            $this->line,
            $this->column,
            $this->endColumn,
            $this->message,
            [...$this->trace, $note],
            $this->fingerprint,
            $this->imprecise,
            $this->sinkIdentity,
            $recorded,
        );
    }
}
