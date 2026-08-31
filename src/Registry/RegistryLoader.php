<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use InvalidArgumentException;
use Throwable;
use Yosymfony\Toml\Toml;

/**
 * Loads TOML registries, resolves `extends`, and validates strictly.
 *
 * Unknown keys are errors, not warnings. A misspelled `clears` in a sanitizer
 * definition would silently stop clearing anything, which turns a working
 * escaper into a permanent false positive — or worse, a misspelled key in a
 * source definition turns a real vulnerability into silence.
 */
final class RegistryLoader
{
    private const META_KEYS = ['name', 'extends', 'description'];

    private const SOURCE_KEYS = [
        'superglobal', 'function', 'class', 'method', 'static_method', 'kinds', 'stored', 'note',
        'arg', 'arg_literal_contains', 'keys', 'key_prefixes', 'sub_keys', 'applies_by',
    ];

    private const SANITIZER_KEYS = [
        'function', 'class', 'method', 'static_method', 'arg', 'args', 'all_args', 'clears',
        'requires_literal_arg', 'literal_violation_rule_id', 'note', 'imprecise',
        'clears_by', 'pattern_arg', 'replacement_arg', 'quoted_only',
    ];

    private const PROPAGATOR_KEYS = ['function', 'class', 'method', 'static_method', 'arg', 'args', 'all_args', 'note'];

    private const SINK_KEYS = [
        'construct', 'function', 'class', 'method', 'static_method', 'arg', 'args', 'all_args',
        'kind', 'severity', 'rule_id', 'note', 'stored_write', 'applies_by',
    ];

    private const SAFE_KEYS = ['function', 'class', 'method', 'static_method', 'note'];

    private const DISPATCHER_KEYS = [
        'function', 'class', 'method', 'static_method',
        'callable', 'mode', 'argument_start', 'returns', 'hook', 'note',
    ];

    private const BYREF_KEYS = [
        'function', 'class', 'method', 'static_method', 'writes', 'from', 'as_container', 'note',
    ];

    private const TEMPLATE_KEYS = [
        'function', 'class', 'method', 'static_method',
        'slug_arg', 'slug', 'name_arg', 'args_arg', 'path_arg', 'note',
    ];

    private const AUTHORIZATION_KEYS = ['function', 'class', 'method', 'static_method', 'proves', 'note'];

    private const CAPABILITY_KEYS = ['name', 'scope', 'note'];

    private const RULE_KEYS = ['id', 'title', 'description', 'remediation', 'cwe', 'message'];

    /**
     * `scan` is not a catalogue section and is ignored here.
     *
     * One `wp-taint.toml` serves both purposes: it extends the catalogue, and
     * it carries the project's `[scan]` paths for {@see ProjectScanConfig}.
     * Splitting them into two files would be tidier and would mean every
     * project keeps two files, so this loader simply knows the key exists.
     */
    private const TABLE_KEYS = [
        'meta', 'sources', 'sanitizers', 'propagators', 'sinks', 'safe', 'dispatchers', 'byref',
        'templates', 'authorization', 'capabilities', 'rules', 'options', 'scan', 'filterable',
    ];

    private const OPTION_KEYS = ['safe_database_identifiers'];

    /** @var list<string> */
    private array $loading = [];

    public function __construct(private readonly string $registryDirectory)
    {
    }

    /**
     * @param string      $nameOrPath a bundled registry name or a path to a TOML file
     * @param string|null $localConfig a project-local `wp-taint.toml`, applied last
     */
    public function load(string $nameOrPath, ?string $localConfig = null): Registry
    {
        $this->loading = [];

        $accumulator = new RegistryAccumulator();
        $names = [];

        $this->loadInto($this->resolvePath($nameOrPath), $accumulator, $names);

        if ($localConfig !== null) {
            $this->loadInto($localConfig, $accumulator, $names);
        }

        return $accumulator->build($names);
    }

    /**
     * @param list<string> $names
     */
    private function loadInto(string $path, RegistryAccumulator $accumulator, array &$names): void
    {
        $canonical = realpath($path);

        if ($canonical === false) {
            throw new RegistryException(sprintf('Registry file not found: %s', $path));
        }

        if (in_array($canonical, $this->loading, true)) {
            throw new RegistryException(sprintf(
                'Circular registry inheritance: %s is already being loaded.',
                $path,
            ));
        }

        $this->loading[] = $canonical;

        $data = $this->parse($canonical);

        $this->rejectUnknownKeys($canonical, 'top level', $data, self::TABLE_KEYS);

        $meta = $this->arrayValue($canonical, 'meta', $data['meta'] ?? []);
        $this->rejectUnknownKeys($canonical, '[meta]', $meta, self::META_KEYS);

        foreach ($this->stringList($canonical, '[meta] extends', $meta['extends'] ?? []) as $parent) {
            $this->loadInto($this->resolvePath($parent), $accumulator, $names);
        }

        $name = $meta['name'] ?? basename($canonical, '.toml');

        if (! is_string($name)) {
            throw RegistryException::at($canonical, '[meta] name', 'must be a string.');
        }

        if (! in_array($name, $names, true)) {
            $names[] = $name;
        }

        $this->loadSources($canonical, $data['sources'] ?? [], $accumulator);
        $this->loadSanitizers($canonical, $data['sanitizers'] ?? [], $accumulator);
        $this->loadPropagators($canonical, $data['propagators'] ?? [], $accumulator);
        $this->loadSinks($canonical, $data['sinks'] ?? [], $accumulator);
        $this->loadSafeCalls($canonical, $data['safe'] ?? [], $accumulator);
        $this->loadDispatchers($canonical, $data['dispatchers'] ?? [], $accumulator);
        $this->loadByRefEffects($canonical, $data['byref'] ?? [], $accumulator);
        $this->loadTemplateLoaders($canonical, $data['templates'] ?? [], $accumulator);
        $this->loadAuthorization($canonical, $data['authorization'] ?? [], $accumulator);
        $this->loadCapabilities($canonical, $data['capabilities'] ?? [], $accumulator);
        $this->loadFilterable($canonical, $data['filterable'] ?? [], $accumulator);
        $this->loadRules($canonical, $data['rules'] ?? [], $accumulator);
        $this->loadOptions($canonical, $data['options'] ?? [], $accumulator);

        array_pop($this->loading);
    }

    /**
     * @return array<string, mixed>
     */
    private function parse(string $path): array
    {
        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new RegistryException(sprintf('Unable to read registry file: %s', $path));
        }

        try {
            $data = Toml::parse($contents);
        } catch (Throwable $error) {
            throw new RegistryException(sprintf('%s: malformed TOML — %s', $path, $error->getMessage()));
        }

        if (! is_array($data)) {
            throw new RegistryException(sprintf('%s: expected a TOML table at the top level.', $path));
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    private function resolvePath(string $nameOrPath): string
    {
        if (str_contains($nameOrPath, '/') || str_ends_with($nameOrPath, '.toml')) {
            return $nameOrPath;
        }

        return $this->registryDirectory . '/' . $nameOrPath . '.toml';
    }

    /**
     */
    private function loadSources(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'sources', $entries) as $index => $entry) {
            $context = sprintf('[[sources]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::SOURCE_KEYS);

            $matcher = $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: true);
            $kinds = $this->kinds($file, $context, $entry['kinds'] ?? null, allowWildcard: false);

            $keys = isset($entry['keys']) ? $this->stringList($file, $context . ' keys', $entry['keys']) : null;

            $accumulator->addSource(new Source(
                $matcher,
                $kinds,
                $this->boolValue($file, $context . ' stored', $entry['stored'] ?? false),
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
                $this->optionalString(
                    $file,
                    $context . ' arg_literal_contains',
                    $entry['arg_literal_contains'] ?? null,
                ),
                $this->intValue($file, $context . ' arg', $entry['arg'] ?? 0),
                $keys,
                $this->stringList($file, $context . ' key_prefixes', $entry['key_prefixes'] ?? []),
                $this->namedStrategy(
                    $file,
                    $context . ' applies_by',
                    $entry['applies_by'] ?? null,
                    Source::STRATEGIES,
                ),
                isset($entry['sub_keys'])
                    ? $this->stringList($file, $context . ' sub_keys', $entry['sub_keys'])
                    : null,
            ));
        }
    }

    private function loadSanitizers(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'sanitizers', $entries) as $index => $entry) {
            $context = sprintf('[[sanitizers]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::SANITIZER_KEYS);

            $matcher = $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false);
            $clearsRaw = $entry['clears'] ?? null;
            $clearsEverything = $this->isWildcard($clearsRaw);
            $clearsBy = $this->clearsBy($file, $context, $entry['clears_by'] ?? null);

            // One or the other. A fixed set and a strategy would leave it
            // ambiguous which one applied, and an entry with neither clears
            // nothing, which is a propagator written in the wrong table.
            if (($clearsBy === null) === ($clearsRaw === null || $clearsRaw === [])) {
                throw RegistryException::at($file, $context, $clearsBy === null
                    ? 'must set either clears or clears_by.'
                    : 'sets both clears and clears_by; a strategy computes what it clears.');
            }

            $accumulator->addSanitizer(new Sanitizer(
                $matcher,
                $this->arguments($file, $context, $entry, ArgumentSelector::index(0)),
                match (true) {
                    $clearsBy !== null => TaintSet::empty(),
                    $clearsEverything => TaintSet::allDataflowKinds(),
                    default => $this->kinds($file, $context, $clearsRaw, allowWildcard: true),
                },
                $clearsEverything,
                isset($entry['requires_literal_arg'])
                    ? $this->intValue($file, $context . ' requires_literal_arg', $entry['requires_literal_arg'])
                    : null,
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
                $this->boolValue($file, $context . ' imprecise', $entry['imprecise'] ?? false),
                $this->optionalString(
                    $file,
                    $context . ' literal_violation_rule_id',
                    $entry['literal_violation_rule_id'] ?? null,
                ),
                $clearsBy,
                $this->intValue($file, $context . ' pattern_arg', $entry['pattern_arg'] ?? 0),
                $this->intValue($file, $context . ' replacement_arg', $entry['replacement_arg'] ?? 1),
                $this->boolValue($file, $context . ' quoted_only', $entry['quoted_only'] ?? false),
            ));
        }
    }

    /**
     * A named strategy for working out what a call clears from its arguments.
     *
     * An unknown name is a hard error rather than a silently inert entry: the
     * whole point of the catalogue being data is that a typo in it cannot
     * quietly disable a sanitizer.
     */
    private function clearsBy(string $file, string $context, mixed $value): ?string
    {
        return $this->namedStrategy($file, $context . ' clears_by', $value, Sanitizer::STRATEGIES);
    }

    /**
     * @param list<string> $allowed
     */
    private function namedStrategy(string $file, string $context, mixed $value, array $allowed): ?string
    {
        if ($value === null) {
            return null;
        }

        $name = $this->requiredString($file, $context, $value);

        if (! in_array($name, $allowed, true)) {
            throw RegistryException::at($file, $context, sprintf(
                '"%s" is not a known strategy. Valid strategies: %s.',
                $name,
                implode(', ', $allowed),
            ));
        }

        return $name;
    }

    private function loadPropagators(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'propagators', $entries) as $index => $entry) {
            $context = sprintf('[[propagators]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::PROPAGATOR_KEYS);

            $accumulator->addPropagator(new Propagator(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $this->arguments($file, $context, $entry, ArgumentSelector::all()),
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
            ));
        }
    }

    private function loadSinks(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'sinks', $entries) as $index => $entry) {
            $context = sprintf('[[sinks]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::SINK_KEYS);

            $kindValue = $this->requiredString($file, $context . ' kind', $entry['kind'] ?? null);
            $kind = TaintKind::tryFrom($kindValue);

            if ($kind === null || ! $kind->isDataflowKind()) {
                throw RegistryException::at($file, $context . ' kind', sprintf(
                    '"%s" is not a taint kind the dataflow engine propagates. Valid kinds: %s.',
                    $kindValue,
                    implode(', ', array_map(
                        static fn (TaintKind $k): string => $k->value,
                        TaintKind::dataflowKinds(),
                    )),
                ));
            }

            $accumulator->addSink(new Sink(
                $this->matcherFor($file, $context, $entry, allowConstruct: true, allowSuperglobal: false),
                $this->arguments($file, $context, $entry, ArgumentSelector::index(0)),
                $kind,
                $this->severity($file, $context, $entry['severity'] ?? null),
                $this->requiredString($file, $context . ' rule_id', $entry['rule_id'] ?? null),
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
                $this->boolValue($file, $context . ' stored_write', $entry['stored_write'] ?? false),
                $this->namedStrategy($file, $context . ' applies_by', $entry['applies_by'] ?? null, Sink::STRATEGIES),
            ));
        }
    }

    private function loadSafeCalls(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'safe', $entries) as $index => $entry) {
            $context = sprintf('[[safe]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::SAFE_KEYS);

            $accumulator->addSafeCall(new SafeCall(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $this->requiredString($file, $context . ' note', $entry['note'] ?? null),
            ));
        }
    }

    private function loadDispatchers(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'dispatchers', $entries) as $index => $entry) {
            $context = sprintf('[[dispatchers]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::DISPATCHER_KEYS);

            $modeValue = $this->requiredString($file, $context . ' mode', $entry['mode'] ?? null);
            $mode = DispatchMode::tryFrom($modeValue);

            if ($mode === null) {
                throw RegistryException::at($file, $context . ' mode', sprintf(
                    '"%s" is not a dispatch mode. Valid modes: %s.',
                    $modeValue,
                    implode(', ', array_map(
                        static fn (DispatchMode $m): string => $m->value,
                        DispatchMode::cases(),
                    )),
                ));
            }

            $returnsValue = $this->requiredString($file, $context . ' returns', $entry['returns'] ?? null);
            $returns = DispatchReturn::tryFrom($returnsValue);

            if ($returns === null) {
                throw RegistryException::at($file, $context . ' returns', sprintf(
                    '"%s" is not a dispatch return. Valid values: %s.',
                    $returnsValue,
                    implode(', ', array_map(
                        static fn (DispatchReturn $r): string => $r->value,
                        DispatchReturn::cases(),
                    )),
                ));
            }

            $callable = $this->intValue($file, $context . ' callable', $entry['callable'] ?? 0);
            $start = $this->intValue($file, $context . ' argument_start', $entry['argument_start'] ?? $callable + 1);

            if ($callable < 0 || $start < 0) {
                throw RegistryException::at($file, $context, 'argument positions cannot be negative.');
            }

            $accumulator->addDispatcher(new Dispatcher(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $callable,
                $mode,
                $start,
                $returns,
                $this->boolValue($file, $context . ' hook', $entry['hook'] ?? false),
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
            ));
        }
    }

    private function loadByRefEffects(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'byref', $entries) as $index => $entry) {
            $context = sprintf('[[byref]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::BYREF_KEYS);

            $writes = $this->intValue($file, $context . ' writes', $entry['writes'] ?? null);
            $from = [];

            foreach ($this->intList($file, $context . ' from', $entry['from'] ?? []) as $source) {
                if ($source === $writes) {
                    throw RegistryException::at($file, $context, 'from cannot include the argument it writes.');
                }

                $from[] = $source;
            }

            if ($writes < 0 || $from === []) {
                throw RegistryException::at(
                    $file,
                    $context,
                    'writes must be a non-negative argument index and from must name at least one argument. An '
                        . 'effect that adds nothing cannot clear anything either, because the lattice only grows.',
                );
            }

            $accumulator->addByRefEffect(new ByRefEffect(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $writes,
                $from,
                $this->boolValue($file, $context . ' as_container', $entry['as_container'] ?? false),
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
            ));
        }
    }

    /**
     * @return list<int>
     */
    private function intList(string $file, string $context, mixed $value): array
    {
        if (! is_array($value)) {
            throw RegistryException::at($file, $context, 'must be a list of argument indexes.');
        }

        $indexes = [];

        foreach ($value as $item) {
            if (! is_int($item) || $item < 0) {
                throw RegistryException::at($file, $context, 'must be a list of non-negative argument indexes.');
            }

            $indexes[] = $item;
        }

        sort($indexes);

        return $indexes;
    }

    private function loadTemplateLoaders(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'templates', $entries) as $index => $entry) {
            $context = sprintf('[[templates]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::TEMPLATE_KEYS);

            $slugArgument = isset($entry['slug_arg'])
                ? $this->intValue($file, $context . ' slug_arg', $entry['slug_arg'])
                : null;
            $slug = $this->optionalString($file, $context . ' slug', $entry['slug'] ?? null);
            $pathArgument = isset($entry['path_arg'])
                ? $this->intValue($file, $context . ' path_arg', $entry['path_arg'])
                : null;

            // Either it names a template, or it is handed one already resolved.
            // An entry that does neither would silently load nothing.
            if ($pathArgument === null && $slugArgument === null && $slug === null) {
                throw RegistryException::at(
                    $file,
                    $context,
                    'must set one of slug, slug_arg or path_arg; without one it names no template.',
                );
            }

            $accumulator->addTemplateLoader(new TemplateLoader(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $slugArgument,
                $slug,
                isset($entry['name_arg'])
                    ? $this->intValue($file, $context . ' name_arg', $entry['name_arg'])
                    : null,
                isset($entry['args_arg'])
                    ? $this->intValue($file, $context . ' args_arg', $entry['args_arg'])
                    : null,
                $pathArgument,
                $this->optionalString($file, $context . ' note', $entry['note'] ?? null),
            ));
        }
    }

    private function loadAuthorization(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'authorization', $entries) as $index => $entry) {
            $context = sprintf('[[authorization]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::AUTHORIZATION_KEYS);

            $proves = $this->optionalString($file, $context . ' proves', $entry['proves'] ?? null) ?? 'entitlement';

            if (! in_array($proves, ['entitlement', 'intent'], true)) {
                throw new RegistryException(sprintf(
                    '%s: %s proves must be "entitlement" or "intent", got "%s".',
                    $file,
                    $context,
                    $proves,
                ));
            }

            $accumulator->addAuthorization(
                $this->matcherFor($file, $context, $entry, allowConstruct: false, allowSuperglobal: false),
                $proves,
            );
        }
    }

    private function loadCapabilities(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'capabilities', $entries) as $index => $entry) {
            $context = sprintf('[[capabilities]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::CAPABILITY_KEYS);

            $scopeValue = $this->requiredString($file, $context . ' scope', $entry['scope'] ?? null);
            $scope = CapabilityScope::tryFrom($scopeValue);

            if ($scope === null) {
                throw RegistryException::at($file, $context . ' scope', sprintf(
                    '"%s" is not a capability scope. Valid scopes: %s.',
                    $scopeValue,
                    implode(', ', array_map(
                        static fn (CapabilityScope $s): string => $s->value,
                        CapabilityScope::cases(),
                    )),
                ));
            }

            $accumulator->addCapability(
                $this->requiredString($file, $context . ' name', $entry['name'] ?? null),
                $scope,
            );
        }
    }

    /**
     * Core functions that return a filtered value.
     *
     * Generated rather than curated — see
     * tools/generate-filterable-catalogue.php — because "which WordPress
     * functions can a plugin rewrite the output of" is a fact about a
     * WordPress checkout, not a judgement call.
     */
    private function loadFilterable(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'filterable', $entries) as $index => $entry) {
            $context = sprintf('[[filterable]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, ['function', 'params', 'note']);

            $accumulator->addFilterable(
                $this->requiredString($file, $context . ' function', $entry['function'] ?? null),
                array_values(array_map(
                    static fn (mixed $index): int => is_int($index) ? $index : 0,
                    $this->arrayValue($file, $context . ' params', $entry['params'] ?? []),
                )),
            );
        }
    }

    private function loadRules(string $file, mixed $entries, RegistryAccumulator $accumulator): void
    {
        foreach ($this->tableList($file, 'rules', $entries) as $index => $entry) {
            $context = sprintf('[[rules]] #%d', $index + 1);
            $this->rejectUnknownKeys($file, $context, $entry, self::RULE_KEYS);

            $accumulator->addRule(new RuleMetadata(
                $this->requiredString($file, $context . ' id', $entry['id'] ?? null),
                $this->requiredString($file, $context . ' title', $entry['title'] ?? null),
                $this->requiredString($file, $context . ' description', $entry['description'] ?? null),
                $this->requiredString($file, $context . ' remediation', $entry['remediation'] ?? null),
                $this->optionalString($file, $context . ' cwe', $entry['cwe'] ?? null),
                $this->optionalString($file, $context . ' message', $entry['message'] ?? null),
            ));
        }
    }

    private function loadOptions(string $file, mixed $options, RegistryAccumulator $accumulator): void
    {
        $options = $this->arrayValue($file, '[options]', $options);
        $this->rejectUnknownKeys($file, '[options]', $options, self::OPTION_KEYS);

        if (isset($options['safe_database_identifiers'])) {
            $accumulator->setSafeDatabaseIdentifiers($this->stringList(
                $file,
                '[options] safe_database_identifiers',
                $options['safe_database_identifiers'],
            ));
        }
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function matcherFor(
        string $file,
        string $context,
        array $entry,
        bool $allowConstruct,
        bool $allowSuperglobal,
    ): Matcher {
        // `class` alone is never a matcher: it only pairs with `method` or
        // `static_method`.
        $primary = array_values(array_filter(
            ['superglobal', 'function', 'construct', 'method', 'static_method'],
            static fn (string $key): bool => isset($entry[$key]),
        ));

        if ($primary === []) {
            throw RegistryException::at(
                $file,
                $context,
                'must declare one of: superglobal, function, construct, method (with class), '
                    . 'static_method (with class).',
            );
        }

        if (count($primary) > 1) {
            throw RegistryException::at($file, $context, sprintf(
                'declares more than one matcher (%s). Each entry matches exactly one thing.',
                implode(', ', $primary),
            ));
        }

        $kind = $primary[0];

        try {
            return match ($kind) {
                'superglobal' => $allowSuperglobal
                    ? Matcher::superglobal(
                        $this->requiredString($file, $context . ' superglobal', $entry['superglobal'] ?? null),
                    )
                    : throw RegistryException::at($file, $context, 'superglobal is only valid in [[sources]].'),
                'construct' => $allowConstruct
                    ? Matcher::construct(
                        $this->requiredString($file, $context . ' construct', $entry['construct'] ?? null),
                    )
                    : throw RegistryException::at($file, $context, 'construct is only valid in [[sinks]].'),
                'function' => Matcher::function(
                    $this->requiredString($file, $context . ' function', $entry['function'] ?? null),
                ),
                'method' => Matcher::method(
                    $this->requiredString($file, $context . ' class', $entry['class'] ?? null),
                    $this->requiredString($file, $context . ' method', $entry['method'] ?? null),
                ),
                default => Matcher::staticMethod(
                    $this->requiredString($file, $context . ' class', $entry['class'] ?? null),
                    $this->requiredString($file, $context . ' static_method', $entry['static_method'] ?? null),
                ),
            };
        } catch (InvalidArgumentException $error) {
            throw RegistryException::at($file, $context, $error->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function arguments(string $file, string $context, array $entry, ArgumentSelector $default): ArgumentSelector
    {
        $declared = array_values(array_filter(
            ['arg', 'args', 'all_args'],
            static fn (string $key): bool => isset($entry[$key]),
        ));

        if (count($declared) > 1) {
            throw RegistryException::at($file, $context, sprintf(
                'declares %s together. Use exactly one of arg, args or all_args.',
                implode(' and ', $declared),
            ));
        }

        if (isset($entry['all_args'])) {
            return $this->boolValue($file, $context . ' all_args', $entry['all_args'])
                ? ArgumentSelector::all()
                : $default;
        }

        if (isset($entry['args'])) {
            $raw = $entry['args'];

            if (! is_array($raw) || $raw === []) {
                throw RegistryException::at($file, $context . ' args', 'must be a non-empty array of integers.');
            }

            $indexes = [];

            foreach ($raw as $value) {
                $indexes[] = $this->intValue($file, $context . ' args', $value);
            }

            return ArgumentSelector::indexes($indexes);
        }

        if (isset($entry['arg'])) {
            return ArgumentSelector::index($this->intValue($file, $context . ' arg', $entry['arg']));
        }

        return $default;
    }

    private function kinds(string $file, string $context, mixed $raw, bool $allowWildcard): TaintSet
    {
        if ($this->isWildcard($raw)) {
            if (! $allowWildcard) {
                throw RegistryException::at(
                    $file,
                    $context . ' kinds',
                    '"*" is not allowed here. List kinds explicitly.',
                );
            }

            return TaintSet::allDataflowKinds();
        }

        $values = $this->stringList($file, $context . ' kinds', $raw);

        if ($values === []) {
            throw RegistryException::at($file, $context . ' kinds', 'must list at least one taint kind.');
        }

        $kinds = [];

        foreach ($values as $value) {
            $kind = TaintKind::tryFrom($value);

            if ($kind === null || ! $kind->isDataflowKind()) {
                throw RegistryException::at($file, $context . ' kinds', sprintf(
                    '"%s" is not a taint kind the dataflow engine propagates. Valid kinds: %s.',
                    $value,
                    implode(', ', array_map(
                        static fn (TaintKind $k): string => $k->value,
                        TaintKind::dataflowKinds(),
                    )),
                ));
            }

            $kinds[] = $kind;
        }

        return TaintSet::of(...$kinds);
    }

    private function severity(string $file, string $context, mixed $raw): Severity
    {
        $value = $this->requiredString($file, $context . ' severity', $raw);

        try {
            return Severity::fromString($value);
        } catch (InvalidArgumentException $error) {
            throw RegistryException::at($file, $context . ' severity', $error->getMessage());
        }
    }

    private function isWildcard(mixed $raw): bool
    {
        return $raw === '*' || $raw === ['*'];
    }

    /**
     * @param array<string, mixed> $entry
     * @param list<string>         $allowed
     */
    private function rejectUnknownKeys(string $file, string $context, array $entry, array $allowed): void
    {
        $unknown = array_values(array_diff(array_keys($entry), $allowed));

        if ($unknown === []) {
            return;
        }

        throw RegistryException::at($file, $context, sprintf(
            'unknown key%s %s. Allowed: %s. A typo in a security catalogue silently creates false negatives, '
                . 'so unknown keys are a hard error.',
            count($unknown) === 1 ? '' : 's',
            implode(', ', array_map(static fn (string $key): string => '"' . $key . '"', $unknown)),
            implode(', ', $allowed),
        ));
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function tableList(string $file, string $table, mixed $entries): array
    {
        if ($entries === []) {
            return [];
        }

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw RegistryException::at($file, '[[' . $table . ']]', 'must be an array of tables.');
        }

        $result = [];

        foreach ($entries as $index => $entry) {
            if (! is_array($entry)) {
                throw RegistryException::at($file, sprintf('[[%s]] #%d', $table, $index + 1), 'must be a table.');
            }

            /** @var array<string, mixed> $entry */
            $result[] = $entry;
        }

        return $result;
    }

    /**
     * @return array<string, mixed>
     */
    private function arrayValue(string $file, string $context, mixed $value): array
    {
        if ($value === []) {
            return [];
        }

        if (! is_array($value)) {
            throw RegistryException::at($file, $context, 'must be a table.');
        }

        $table = [];

        foreach ($value as $key => $item) {
            $table[(string) $key] = $item;
        }

        return $table;
    }

    /**
     * @return list<string>
     */
    private function stringList(string $file, string $context, mixed $value): array
    {
        if ($value === null || $value === []) {
            return [];
        }

        if (is_string($value)) {
            return [$value];
        }

        if (! is_array($value)) {
            throw RegistryException::at($file, $context, 'must be a string or an array of strings.');
        }

        $result = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw RegistryException::at($file, $context, 'must contain strings only.');
            }

            $result[] = $item;
        }

        return $result;
    }

    private function requiredString(string $file, string $context, mixed $value): string
    {
        if (! is_string($value) || $value === '') {
            throw RegistryException::at($file, $context, 'is required and must be a non-empty string.');
        }

        return $value;
    }

    private function optionalString(string $file, string $context, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        return $this->requiredString($file, $context, $value);
    }

    private function intValue(string $file, string $context, mixed $value): int
    {
        if (! is_int($value) || $value < 0) {
            throw RegistryException::at($file, $context, 'must be a non-negative integer.');
        }

        return $value;
    }

    private function boolValue(string $file, string $context, mixed $value): bool
    {
        if (! is_bool($value)) {
            throw RegistryException::at($file, $context, 'must be true or false.');
        }

        return $value;
    }
}
