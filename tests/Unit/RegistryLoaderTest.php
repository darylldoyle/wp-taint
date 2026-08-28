<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\RegistryException;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Taint\TaintKind;

function writeRegistry(string $toml): string
{
    $directory = sys_get_temp_dir() . '/wp-taint-registry-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);
    $path = $directory . '/custom.toml';
    file_put_contents($path, $toml);

    return $path;
}

function loadRegistry(string $toml): Registry
{
    return (new RegistryLoader(registryDirectory()))->load(writeRegistry($toml));
}

it('loads the bundled registries and resolves inheritance', function (): void {
    $registry = testRegistry();

    expect($registry->names)->toBe(['php-core', 'wordpress-generated', 'wordpress-filterable', 'wordpress']);
    expect($registry->source(Matcher::superglobal('_GET')))->not->toBeNull();
    expect($registry->sanitizer(Matcher::function('esc_html')))->not->toBeNull();
    expect($registry->sinksFor(Matcher::construct('echo')))->not->toBeEmpty();
});

it('applies later definitions over earlier ones', function (): void {
    $registry = loadRegistry(<<<'TOML'
        [meta]
        name = "custom"
        extends = ["wordpress"]

        [[sanitizers]]
        function = "esc_url_raw"
        clears = ["html", "html_attr", "url"]
        note = "A project that has audited its own usage."
        TOML);

    $sanitizer = $registry->sanitizer(Matcher::function('esc_url_raw'));

    expect($sanitizer)->not->toBeNull();
    expect($sanitizer->clears->has(TaintKind::Html))->toBeTrue();
});

it('moves an entry between roles rather than leaving both in place', function (): void {
    // Redefining a propagator as a sanitizer is a deliberate override. Leaving
    // both would make the winner depend on lookup order.
    $registry = loadRegistry(<<<'TOML'
        [meta]
        name = "custom"
        extends = ["wordpress"]

        [[sanitizers]]
        function = "wp_unslash"
        clears = ["html"]
        TOML);

    expect($registry->sanitizer(Matcher::function('wp_unslash')))->not->toBeNull();
    expect($registry->propagator(Matcher::function('wp_unslash')))->toBeNull();
});

it('treats an unknown key as a hard error', function (): void {
    // A typo in a security catalogue silently creates false negatives.
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[sanitizers]]
        function = "esc_html"
        clesrs = ["html"]
        TOML))->toThrow(RegistryException::class, 'unknown key "clesrs"');
});

it('names the file and the entry in every error', function (): void {
    try {
        loadRegistry(<<<'TOML'
            [meta]
            name = "custom"

            [[sinks]]
            function = "printf"
            kind = "html"
            rule_id = "x"
            TOML);

        expect(false)->toBeTrue('expected a RegistryException');
    } catch (RegistryException $error) {
        expect($error->getMessage())->toContain('custom.toml');
        expect($error->getMessage())->toContain('[[sinks]] #1');
        expect($error->getMessage())->toContain('severity');
    }
});

it('rejects an entry with no matcher', function (): void {
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[propagators]]
        note = "no matcher at all"
        TOML))->toThrow(RegistryException::class, 'must declare one of');
});

it('rejects a construct outside [[sinks]]', function (): void {
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[sanitizers]]
        construct = "echo"
        clears = ["html"]
        TOML))->toThrow(RegistryException::class, 'unknown key "construct"');
});

it('rejects an entry with two matchers', function (): void {
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[propagators]]
        function = "trim"
        class = "wpdb"
        method = "prepare"
        TOML))->toThrow(RegistryException::class, 'declares more than one matcher');
});

it('rejects arg and args together', function (): void {
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[propagators]]
        function = "trim"
        arg = 0
        args = [1]
        TOML))->toThrow(RegistryException::class, 'Use exactly one of arg, args or all_args');
});

it('rejects the authz category anywhere a taint kind is expected', function (): void {
    // Authz is a finding category, not something the dataflow engine carries.
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[sources]]
        function = "acme_get"
        kinds = ["authz"]
        TOML))->toThrow(RegistryException::class, 'is not a taint kind');
});

it('refuses to let a safe call be re-added as a sink', function (): void {
    // wpdb::insert() escapes internally. Flagging it is a guaranteed false
    // positive, and the [[safe]] list is enforced rather than advisory.
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"
        extends = ["wordpress"]

        [[sinks]]
        class = "wpdb"
        method = "insert"
        arg = 1
        kind = "sql"
        severity = "critical"
        rule_id = "wp.sqli.wpdb-query"
        TOML))->toThrow(RegistryException::class, 'also listed under [[safe]]');
});

it('requires rule metadata for every rule a sink can emit', function (): void {
    expect(static fn (): Registry => loadRegistry(<<<'TOML'
        [meta]
        name = "custom"

        [[sinks]]
        function = "acme_render"
        kind = "html"
        severity = "high"
        rule_id = "acme.undocumented"
        TOML))->toThrow(RegistryException::class, 'No [[rules]] metadata for: acme.undocumented');
});

it('refuses a circular extends chain', function (): void {
    $directory = sys_get_temp_dir() . '/wp-taint-cycle-' . bin2hex(random_bytes(6));
    mkdir($directory, 0o755, true);

    file_put_contents($directory . '/a.toml', "[meta]\nname = \"a\"\nextends = [\"" . $directory . "/b.toml\"]\n");
    file_put_contents($directory . '/b.toml', "[meta]\nname = \"b\"\nextends = [\"" . $directory . "/a.toml\"]\n");

    expect(fn (): Registry => (new RegistryLoader(registryDirectory()))->load($directory . '/a.toml'))
        ->toThrow(RegistryException::class, 'Circular registry inheritance');
});

it('reports a missing registry file by name', function (): void {
    expect(fn (): Registry => (new RegistryLoader(registryDirectory()))->load('does-not-exist'))
        ->toThrow(RegistryException::class, 'Registry file not found');
});

it('reports malformed TOML rather than silently loading nothing', function (): void {
    expect(static fn (): Registry => loadRegistry("[meta\nname = broken"))
        ->toThrow(RegistryException::class, 'malformed TOML');
});

it('layers a project-local config last', function (): void {
    $local = writeRegistry(<<<'TOML'
        [meta]
        name = "project"

        [[sanitizers]]
        function = "acme_escape"
        clears = ["html"]
        TOML);

    $registry = (new RegistryLoader(registryDirectory()))->load('wordpress', $local);

    expect($registry->sanitizer(Matcher::function('acme_escape')))->not->toBeNull();
    expect($registry->names)->toBe(['php-core', 'wordpress-generated', 'wordpress-filterable', 'wordpress', 'project']);
});

it('sorts every catalogue map so registry:dump is diffable', function (): void {
    $registry = testRegistry();

    foreach (
        [
        $registry->sources(),
        $registry->sanitizers(),
        $registry->propagators(),
        $registry->sinks(),
        $registry->rules(),
        ] as $entries
    ) {
        $keys = array_keys($entries);
        $sorted = $keys;
        sort($sorted);

        expect($keys)->toBe($sorted);
    }
});

it('keeps the generated catalogue in sync with WPCS', function (): void {
    // The generated file is checked in so the diff is reviewable — a generated
    // security catalogue nobody reads is worse than a short one somebody wrote.
    // This fails if WPCS moved and nobody regenerated.
    $process = new Symfony\Component\Process\Process(
        ['php', 'tools/generate-wpcs-catalogue.php', '--check'],
        projectRoot(),
    );
    $process->run();

    expect($process->getExitCode())->toBe(
        0,
        "Generated catalogue is stale. Run: composer catalogue:generate\n" . $process->getErrorOutput(),
    );
});

it('lets a hand-written entry beat a generated one', function (): void {
    // The whole reason the generated file is loaded first. WPCS says esc_url_raw
    // escapes; it does not say it is not an HTML escaper, and that distinction
    // is the difference between a real finding and a laundered one.
    $registry = (new Enshrined\WpTaint\Registry\RegistryLoader(projectRoot() . '/registries'))->load('wordpress');

    $clears = $registry->sanitizer(Enshrined\WpTaint\Registry\Matcher::function('esc_url_raw'));

    expect($clears)->not->toBeNull();
    expect($clears->describeClears())->toBe('url');
});
