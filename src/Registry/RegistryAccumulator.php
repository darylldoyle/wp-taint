<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * Collects entries across an inheritance chain, applying override precedence.
 *
 * Later definitions replace earlier ones by matcher key. That is why the
 * `extends` chain is loaded depth-first, base first.
 */
final class RegistryAccumulator
{
    /** @var array<string, Source> */
    private array $sources = [];

    /** @var array<string, Sanitizer> */
    private array $sanitizers = [];

    /** @var array<string, Propagator> */
    private array $propagators = [];

    /** @var array<string, list<Sink>> */
    private array $sinks = [];

    /** @var array<string, SafeCall> */
    private array $safeCalls = [];

    /** @var array<string, Dispatcher> */
    private array $dispatchers = [];

    /** @var array<string, ByRefEffect> */
    private array $byRef = [];

    /** @var array<string, TemplateLoader> */
    private array $templates = [];

    /** @var array<string, true> */
    /** @var array<string, string> identity => "entitlement" or "intent" */
    private array $authorization = [];

    /** @var array<string, CapabilityScope> capability name => what a passing check proves */
    private array $capabilities = [];

    /** @var array<string, list<int>> lowercased name => parameter indices the filtered return comes from */
    private array $filterable = [];

    /** @var array<string, RuleMetadata> */
    private array $rules = [];

    /** @var list<string> */
    private array $safeDatabaseIdentifiers = [];

    public function addSource(Source $source): void
    {
        $this->sources[$source->matcher->key()] = $source;
    }

    public function addSanitizer(Sanitizer $sanitizer): void
    {
        $key = $sanitizer->matcher->key();
        $this->sanitizers[$key] = $sanitizer;

        // An entry can only be one thing. Redefining a propagator as a
        // sanitizer is a deliberate, meaningful override; leaving both in place
        // would make the winner depend on lookup order.
        unset($this->propagators[$key]);
    }

    public function addPropagator(Propagator $propagator): void
    {
        $key = $propagator->matcher->key();
        $this->propagators[$key] = $propagator;
        unset($this->sanitizers[$key]);
    }

    /**
     * One function can be several sinks.
     *
     * `update_option( $name, $value )` is a stored-taint sink on the value and
     * a privilege-escalation sink on the name — different kinds, different
     * severities, different rules. Keying by matcher alone kept only whichever
     * entry the loader saw last and dropped the other without a word, which is
     * the one failure mode this registry is otherwise built to prevent.
     */
    public function addSink(Sink $sink): void
    {
        $this->sinks[$sink->matcher->key()][] = $sink;
    }

    public function addSafeCall(SafeCall $safeCall): void
    {
        $this->safeCalls[$safeCall->matcher->key()] = $safeCall;
    }

    public function addDispatcher(Dispatcher $dispatcher): void
    {
        $this->dispatchers[$dispatcher->matcher->key()] = $dispatcher;
    }

    public function addTemplateLoader(TemplateLoader $loader): void
    {
        $this->templates[$loader->matcher->key()] = $loader;
    }

    public function addByRefEffect(ByRefEffect $effect): void
    {
        $this->byRef[$effect->matcher->key()] = $effect;
    }

    public function addAuthorization(Matcher $matcher, string $proves): void
    {
        $this->authorization[$matcher->identity()] = $proves;
    }

    public function addCapability(string $name, CapabilityScope $scope): void
    {
        $this->capabilities[strtolower($name)] = $scope;
    }

    /**
     * @param array<array-key, int> $params
     */
    public function addFilterable(string $function, array $params = []): void
    {
        $this->filterable[strtolower(ltrim($function, '\\'))] = array_values($params);
    }

    public function addRule(RuleMetadata $rule): void
    {
        $this->rules[$rule->id] = $rule;
    }

    /**
     * @param list<string> $identifiers
     */
    public function setSafeDatabaseIdentifiers(array $identifiers): void
    {
        $this->safeDatabaseIdentifiers = $identifiers;
    }

    /**
     * @param list<string> $names
     */
    public function build(array $names): Registry
    {
        $this->assertSinksAreNotAlsoSafe();
        $this->assertSinkRulesHaveMetadata();

        ksort($this->sources);
        ksort($this->sanitizers);
        ksort($this->propagators);
        ksort($this->sinks);
        ksort($this->safeCalls);
        ksort($this->dispatchers);
        ksort($this->byRef);
        ksort($this->templates);
        ksort($this->authorization);
        ksort($this->capabilities);
        ksort($this->filterable);
        ksort($this->rules);

        $identifiers = $this->safeDatabaseIdentifiers;
        sort($identifiers);

        return new Registry(
            $names,
            $this->sources,
            $this->sanitizers,
            $this->propagators,
            $this->sinks,
            $this->safeCalls,
            $this->dispatchers,
            $this->byRef,
            $this->templates,
            $this->authorization,
            $this->capabilities,
            $this->filterable,
            $this->rules,
            $identifiers,
        );
    }

    /**
     * `wpdb::insert()` and friends escape internally. Listing them under
     * `[[safe]]` is not a comment — it is enforced here, so that adding them
     * back as sinks fails loudly instead of shipping a guaranteed false
     * positive.
     */
    private function assertSinksAreNotAlsoSafe(): void
    {
        $collisions = array_intersect(array_keys($this->sinks), array_keys($this->safeCalls));

        if ($collisions === []) {
            return;
        }

        $descriptions = [];

        foreach ($collisions as $key) {
            $safe = $this->safeCalls[$key] ?? null;

            if ($safe === null) {
                continue;
            }

            $descriptions[] = sprintf('%s (marked safe: %s)', $safe->matcher->describe(), $safe->note);
        }

        throw new RegistryException(sprintf(
            "The following are declared as sinks but are also listed under [[safe]]:\n  %s\n"
                . 'Remove the sink entry, or remove the [[safe]] entry and say why in the commit.',
            implode("\n  ", $descriptions),
        ));
    }

    /**
     * Every rule a sink can emit must have metadata, because JSON output
     * carries the rule definition inline and an agent reading it cold has no
     * other source for it.
     */
    private function assertSinkRulesHaveMetadata(): void
    {
        $missing = [];

        foreach ($this->sinks as $sinks) {
            foreach ($sinks as $sink) {
                if (isset($this->rules[$sink->ruleId])) {
                    continue;
                }

                $missing[$sink->ruleId] = true;
            }
        }

        if ($missing === []) {
            return;
        }

        $ids = array_keys($missing);
        sort($ids);

        throw new RegistryException(sprintf(
            "No [[rules]] metadata for: %s.\n"
                . 'Every rule id emitted by a sink needs a title, description and remediation.',
            implode(', ', $ids),
        ));
    }
}
