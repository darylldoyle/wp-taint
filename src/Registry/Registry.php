<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Finding\RuleDefinition;
use Enshrined\WpTaint\Finding\Severity;

/**
 * The fully resolved catalogue: sources, sanitizers, propagators, sinks, the
 * explicitly-safe list, and rule metadata.
 *
 * Everything here is data loaded from TOML. Adding a WordPress escaper must
 * never require a code change.
 */
final class Registry
{
    /**
     * @param list<string>                $names       the registry chain, base first
     * @param array<string, Source>       $sources
     * @param array<string, Sanitizer>    $sanitizers
     * @param array<string, Propagator>   $propagators
     * @param array<string, Sink>         $sinks
     * @param array<string, SafeCall>     $safeCalls
     * @param array<string, Dispatcher>   $dispatchers
     * @param array<string, RuleMetadata> $rules
     * @param list<string>                $safeDatabaseIdentifiers
     */
    public function __construct(
        public readonly array $names,
        private readonly array $sources,
        private readonly array $sanitizers,
        private readonly array $propagators,
        private readonly array $sinks,
        private readonly array $safeCalls,
        private readonly array $dispatchers,
        private readonly array $rules,
        private readonly array $safeDatabaseIdentifiers,
    ) {
    }

    public function source(Matcher $matcher): ?Source
    {
        return $this->sources[$matcher->key()] ?? null;
    }

    public function sanitizer(Matcher $matcher): ?Sanitizer
    {
        return $this->sanitizers[$matcher->key()] ?? null;
    }

    public function propagator(Matcher $matcher): ?Propagator
    {
        return $this->propagators[$matcher->key()] ?? null;
    }

    public function sink(Matcher $matcher): ?Sink
    {
        return $this->sinks[$matcher->key()] ?? null;
    }

    /**
     * The dispatcher entry for a call, if this call runs something else.
     */
    public function dispatcher(Matcher $matcher): ?Dispatcher
    {
        return $this->dispatchers[$matcher->key()] ?? null;
    }

    /**
     * @return array<string, Dispatcher>
     */
    public function dispatchers(): array
    {
        return $this->dispatchers;
    }

    public function isSafeCall(Matcher $matcher): bool
    {
        return isset($this->safeCalls[$matcher->key()]);
    }

    /**
     * True when a call is known to the catalogue in any capacity.
     *
     * Used to decide whether an unresolved call is "an external function we
     * have no model for" or "a function we have deliberately modelled as
     * neutral".
     */
    public function knows(Matcher $matcher): bool
    {
        $key = $matcher->key();

        return isset($this->sources[$key])
            || isset($this->sanitizers[$key])
            || isset($this->propagators[$key])
            || isset($this->sinks[$key])
            || isset($this->safeCalls[$key]);
    }

    /**
     * Property names on `$wpdb` that hold table names.
     *
     * Interpolating `{$wpdb->prefix}` into a `prepare()` format string is the
     * standard, correct WordPress idiom. Treating it as a non-literal argument
     * would produce a false positive on nearly every plugin in existence.
     *
     * @return list<string>
     */
    public function safeDatabaseIdentifiers(): array
    {
        return $this->safeDatabaseIdentifiers;
    }

    public function rule(string $ruleId): RuleDefinition
    {
        $metadata = $this->rules[$ruleId] ?? null;

        if ($metadata !== null) {
            return $metadata->toDefinition();
        }

        return new RuleDefinition(
            $ruleId,
            $ruleId,
            'No rule metadata is registered for this rule id.',
            'Add a [[rules]] entry for this rule id to the registry.',
        );
    }

    public function ruleMessage(string $ruleId): string
    {
        return ($this->rules[$ruleId] ?? null)?->message() ?? $ruleId;
    }

    public function hasRule(string $ruleId): bool
    {
        return isset($this->rules[$ruleId]);
    }

    /**
     * Severity for a rule that is not declared on a sink — the structural
     * rules, which have no `[[sinks]]` entry of their own.
     */
    public function severityForRule(string $ruleId, Severity $default): Severity
    {
        foreach ($this->sinks as $sink) {
            if ($sink->ruleId === $ruleId) {
                return $sink->severity;
            }
        }

        return $default;
    }

    /**
     * @return array<string, Source>
     */
    public function sources(): array
    {
        return $this->sources;
    }

    /**
     * @return array<string, Sanitizer>
     */
    public function sanitizers(): array
    {
        return $this->sanitizers;
    }

    /**
     * @return array<string, Propagator>
     */
    public function propagators(): array
    {
        return $this->propagators;
    }

    /**
     * @return array<string, Sink>
     */
    public function sinks(): array
    {
        return $this->sinks;
    }

    /**
     * @return array<string, SafeCall>
     */
    public function safeCalls(): array
    {
        return $this->safeCalls;
    }

    /**
     * @return array<string, RuleMetadata>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /**
     * Apply the two catalogue switches the CLI exposes.
     *
     * Stored *reads* are on by default, because stored XSS is most of the
     * WordPress CVE population. Stored *writes* are off by default, because on
     * most codebases they dominate the output and bury everything else.
     */
    public function configured(bool $storedTaint, bool $storedTaintWrites): self
    {
        $registry = $storedTaint ? $this : $this->withoutStoredSources();

        return $storedTaintWrites ? $registry : $registry->withoutStoredWriteSinks();
    }

    /**
     * Drop stored (second-order) sources, for `--no-stored-taint`.
     */
    public function withoutStoredSources(): self
    {
        $sources = array_filter($this->sources, static fn (Source $source): bool => ! $source->stored);

        return new self(
            $this->names,
            $sources,
            $this->sanitizers,
            $this->propagators,
            $this->sinks,
            $this->safeCalls,
            $this->dispatchers,
            $this->rules,
            $this->safeDatabaseIdentifiers,
        );
    }

    /**
     * Drop stored-write sinks unless `--stored-taint-writes` was passed.
     */
    public function withoutStoredWriteSinks(): self
    {
        $sinks = array_filter($this->sinks, static fn (Sink $sink): bool => ! $sink->storedWrite);

        return new self(
            $this->names,
            $this->sources,
            $this->sanitizers,
            $this->propagators,
            $sinks,
            $this->safeCalls,
            $this->dispatchers,
            $this->rules,
            $this->safeDatabaseIdentifiers,
        );
    }
}
