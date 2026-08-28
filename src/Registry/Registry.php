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
     * @param array<string, list<Sink>>   $sinks
     * @param array<string, SafeCall>     $safeCalls
     * @param array<string, Dispatcher>   $dispatchers
     * @param array<string, ByRefEffect>  $byRef         calls that write back through an argument
     * @param array<string, TemplateLoader> $templates   calls that load a theme template by name
     * @param array<string, string>       $authorization matcher identity => what it proves, "entitlement" or "intent"
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
        private readonly array $byRef,
        private readonly array $templates,
        private readonly array $authorization,
        /** @var array<string, list<int>> */
        private readonly array $filterable,
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

    /**
     * Every sink role this call plays.
     *
     * A list, because one function can be a sink more than once: the option
     * name and the option value are separate arguments, separate kinds and
     * separate rules.
     *
     * @return list<Sink>
     */
    public function sinksFor(Matcher $matcher): array
    {
        return $this->sinks[$matcher->key()] ?? [];
    }

    public function isSink(Matcher $matcher): bool
    {
        return isset($this->sinks[$matcher->key()]);
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

    /**
     * The template this call loads, if it loads one by name.
     */
    public function templateLoader(Matcher $matcher): ?TemplateLoader
    {
        return $this->templates[$matcher->key()] ?? null;
    }

    /**
     * @return array<string, TemplateLoader>
     */
    public function templateLoaders(): array
    {
        return $this->templates;
    }

    /**
     * The by-reference effect of a call, if it writes back through an argument.
     */
    public function byRefEffect(Matcher $matcher): ?ByRefEffect
    {
        return $this->byRef[$matcher->key()] ?? null;
    }

    /**
     * @return array<string, ByRefEffect>
     */
    public function byRefEffects(): array
    {
        return $this->byRef;
    }

    /**
     * Calls that constitute an authorization check of any kind.
     *
     * Returned as matcher identities so the call graph can be walked without
     * reconstructing a Matcher per edge. Data rather than a constant, so a
     * project can name its own gatekeeper.
     *
     * @return list<string>
     */
    public function authorizationChecks(): array
    {
        return array_keys($this->authorization);
    }

    /**
     * Calls that establish the caller may do the thing, as opposed to meaning
     * to do it.
     *
     * A nonce proves intent: this request came from a form we rendered, so it
     * is not cross-site. It says nothing about entitlement, and a subscriber
     * can obtain a perfectly valid nonce for a form they should never be able
     * to submit. `check_admin_referer()` in a row-deletion handler stops the
     * attack from being CSRF and leaves it a privilege escalation.
     *
     * The distinction exists because the AJAX rule accepts either — changing
     * that would move findings across every plugin in the corpus — while the
     * admin_post_ rule requires entitlement, which is the correct bar and the
     * only reason it catches what it was written for.
     *
     * @return list<string>
     */
    public function entitlementChecks(): array
    {
        return array_keys(array_filter(
            $this->authorization,
            static fn (string $proves): bool => $proves === 'entitlement',
        ));
    }

    /**
     * Does this function return a value a plugin can rewrite?
     *
     * `get_the_title()` runs `the_title` inside it, so escaping done before the
     * call does not survive it. Generated from a WordPress checkout rather than
     * guessed at by name — see tools/generate-filterable-catalogue.php.
     */
    /**
     * The parameters whose value comes back out of this function's filter.
     *
     * Null when the function does not return a filtered value at all. The
     * distinction between that and an empty list matters: `get_the_title( $id )`
     * filters a title it fetched itself, so an escaped `$id` never reaches the
     * output and nothing is voided.
     *
     * @return list<int>|null
     */
    public function filterableParameters(string $function): ?array
    {
        return $this->filterable[strtolower(ltrim($function, '\\'))] ?? null;
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
        foreach ($this->sinks as $sinks) {
            foreach ($sinks as $sink) {
                if ($sink->ruleId === $ruleId) {
                    return $sink->severity;
                }
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
     * @return array<string, list<Sink>>
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
            $this->byRef,
            $this->templates,
            $this->authorization,
            $this->filterable,
            $this->rules,
            $this->safeDatabaseIdentifiers,
        );
    }

    /**
     * Drop stored-write sinks unless `--stored-taint-writes` was passed.
     *
     * Filters within each matcher's list rather than dropping the matcher, so
     * that turning stored writes off on update_option() leaves its other role —
     * the option name as a privileged identifier — switched on.
     */
    public function withoutStoredWriteSinks(): self
    {
        $sinks = array_filter(array_map(
            static fn (array $forMatcher): array => array_values(array_filter(
                $forMatcher,
                static fn (Sink $sink): bool => ! $sink->storedWrite,
            )),
            $this->sinks,
        ), static fn (array $forMatcher): bool => $forMatcher !== []);

        return new self(
            $this->names,
            $this->sources,
            $this->sanitizers,
            $this->propagators,
            $sinks,
            $this->safeCalls,
            $this->dispatchers,
            $this->byRef,
            $this->templates,
            $this->authorization,
            $this->filterable,
            $this->rules,
            $this->safeDatabaseIdentifiers,
        );
    }
}
