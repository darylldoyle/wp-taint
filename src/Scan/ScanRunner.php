<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Enshrined\WpTaint\Cli\ScanConfiguration;

/**
 * Wraps {@see Scanner} with the result cache.
 *
 * The cache is keyed on everything that can change the answer: the tool
 * version, the resolved catalogue, the analysis options, and the content of
 * every file in the scan. Anything else would risk serving a stale clean
 * result, which in a security scanner is the same as lying.
 *
 * Because the analysis is whole-program — interprocedural taint crosses files —
 * the only sound cache unit is the whole scan. Caching a single file's findings
 * would be wrong the moment a function it calls changed in another file.
 */
final class ScanRunner
{
    public function __construct(private readonly ScanConfiguration $configuration)
    {
    }

    /**
     * @param list<string> $files
     */
    public function run(array $files): ScanResult
    {
        $scanner = new Scanner(
            $this->configuration->registry,
            $this->configuration->analysis,
            $this->configuration->root,
            $this->configuration->structuralRules,
            $this->configuration->dumpTaintGraph,
        );

        // A graph dump is a side effect the cache cannot replay, so it always
        // forces a real run.
        if (! $this->configuration->useCache || $this->configuration->dumpTaintGraph !== null) {
            return $scanner->scan($files);
        }

        $cache = new ResultCache($this->cacheDirectory());
        $key = $cache->key($files, $this->fingerprint());

        $cached = $cache->get($key);

        if ($cached !== null) {
            return $cached;
        }

        $result = $scanner->scan($files);
        $cache->put($key, $result);

        return $result;
    }

    private function cacheDirectory(): string
    {
        if ($this->configuration->cacheDirectory !== null) {
            return $this->configuration->cacheDirectory;
        }

        return sys_get_temp_dir() . '/wp-taint-cache';
    }

    /**
     * Everything except the file contents that can change the result.
     */
    private function fingerprint(): string
    {
        $analysis = $this->configuration->analysis;
        $registry = $this->configuration->registry;

        return hash('sha256', serialize([
            'version' => \Enshrined\WpTaint\Cli\Application::VERSION,
            'registries' => $registry->names,
            'sources' => array_keys($registry->sources()),
            'sanitizers' => array_keys($registry->sanitizers()),
            'propagators' => array_keys($registry->propagators()),
            'sinks' => array_keys($registry->sinks()),
            'safe' => array_keys($registry->safeCalls()),
            'identifiers' => $registry->safeDatabaseIdentifiers(),
            'interprocedural' => $analysis->interprocedural,
            'assumeDynamicTainted' => $analysis->assumeDynamicTainted,
            'structuralRules' => $this->configuration->structuralRules,
            'root' => $this->configuration->root,
        ]));
    }
}
