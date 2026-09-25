<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\DynamicCallPolicy;
use InvalidArgumentException;
use RuntimeException;

/**
 * Everything a scan needs, resolved from the command line in one place.
 *
 * Kept separate from the command so that tests can build a configuration
 * without going through Symfony Console.
 */
final class ScanConfiguration
{
    /**
     * 4GB for the graph cache, on top of what the scan needs anyway.
     *
     * Chosen for a 32GB machine scanning a client site with its whole plugins
     * directory as reference: that scan's tables take about 5GB, and every
     * graph together about 21GB. With 4GB of them held, the peak is about 9GB
     * and the scan rebuilds about two and a half graphs per file. A project
     * that fits whole in 4GB never rebuilds anything. See
     * docs/design/two-pass-engine.md.
     */
    public const DEFAULT_MEMORY_BUDGET = 4 * 1024 * 1024 * 1024;

    /**
     * @param list<string> $paths
     * @param list<string> $excludes
     * @param list<string> $includePaths analysed for symbols, never reported on
     */
    public function __construct(
        public readonly array $paths,
        public readonly string $root,
        public readonly Registry $registry,
        public readonly AnalysisOptions $analysis,
        public readonly array $excludes,
        public readonly string $format,
        public readonly ?string $output,
        public readonly ?string $baselinePath,
        public readonly ?string $generateBaselinePath,
        public readonly Severity $minimumSeverity,
        public readonly ?Severity $failOn,
        public readonly bool $parseReport,
        public readonly ?string $dumpTaintGraph,
        public readonly bool $structuralRules,
        public readonly int $jobs,
        public readonly array $includePaths = [],
        public readonly bool $honorPhpcsSuppressions = true,
        /**
         * Bytes of parsed files the scan may hold, or null for no limit. See
         * {@see self::DEFAULT_MEMORY_BUDGET}.
         */
        public readonly ?int $memoryBudget = self::DEFAULT_MEMORY_BUDGET,
    ) {
    }

    /**
     * @param list<string> $paths
     * @param list<string> $excludes
     * @param list<string> $includePaths
     */
    public static function build(
        array $paths,
        string $registryName,
        ?string $configPath,
        array $excludes,
        string $format,
        ?string $output,
        ?string $baselinePath,
        ?string $generateBaselinePath,
        string $minimumSeverity,
        ?string $failOn,
        bool $interprocedural,
        bool $storedTaint,
        bool $storedTaintWrites,
        DynamicCallPolicy $dynamicCalls,
        bool $followIncludes,
        bool $unknownProvenance,
        /** @var list<string> */
        array $includePaths,
        bool $parseReport,
        ?string $dumpTaintGraph,
        bool $structuralRules,
        int $jobs,
        bool $honorPhpcsSuppressions = true,
        ?string $memoryBudget = null,
    ): self {
        if ($paths === []) {
            throw new InvalidArgumentException('At least one path to scan is required.');
        }

        $root = PathHelper::commonRoot($paths);
        $config = $configPath ?? self::discoverLocalConfig($root, $paths);

        if ($configPath !== null && ! is_file($configPath)) {
            throw new RuntimeException(sprintf('Config file not found: %s', $configPath));
        }

        $registry = (new RegistryLoader(Application::registryDirectory()))
            ->load($registryName, $config)
            ->configured($storedTaint, $storedTaintWrites);

        if (! in_array($format, ['console', 'json', 'sarif'], true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown format "%s". Expected one of: console, json, sarif.',
                $format,
            ));
        }

        if ($jobs < 1) {
            throw new InvalidArgumentException('--jobs must be at least 1.');
        }

        return new self(
            $paths,
            $root,
            $registry,
            new AnalysisOptions(
                interprocedural: $interprocedural,
                dynamicCalls: $dynamicCalls,
                followIncludes: $followIncludes,
                unknownProvenance: $unknownProvenance,
            ),
            $excludes,
            $format,
            $output,
            $baselinePath,
            $generateBaselinePath,
            Severity::fromString($minimumSeverity),
            $failOn === null || $failOn === 'never' ? null : Severity::fromString($failOn),
            $parseReport,
            $dumpTaintGraph,
            $structuralRules,
            $jobs,
            array_values(array_map(
                static fn (string $path): string => rtrim($path, '/'),
                array_values($includePaths),
            )),
            $honorPhpcsSuppressions,
            $memoryBudget === null ? self::DEFAULT_MEMORY_BUDGET : self::memoryBudget($memoryBudget),
        );
    }

    /**
     * Bytes from `4G`, `512M`, `750K` or a plain number, or null from
     * `unlimited`.
     */
    public static function memoryBudget(string $value): ?int
    {
        $value = strtolower(trim($value));

        if ($value === 'unlimited') {
            return null;
        }

        if (preg_match('/^(\d+)([kmg]?)b?$/', $value, $match) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Unknown memory budget "%s". Expected a size such as 4G, 512M or 0, or "unlimited".',
                $value,
            ));
        }

        $multiplier = match ($match[2]) {
            'k' => 1024,
            'm' => 1024 * 1024,
            'g' => 1024 * 1024 * 1024,
            default => 1,
        };

        return (int) $match[1] * $multiplier;
    }

    /**
     * A project-local `wp-taint.toml` in the scan root, loaded last so it can
     * add to or override anything in the bundled catalogue.
     *
     * @param list<string> $paths
     */
    private static function discoverLocalConfig(string $root, array $paths): ?string
    {
        $candidates = [$root . '/wp-taint.toml'];

        foreach ($paths as $path) {
            $directory = is_dir($path) ? $path : dirname($path);
            $candidates[] = rtrim($directory, '/') . '/wp-taint.toml';
        }

        $candidates[] = getcwd() . '/wp-taint.toml';

        foreach ($candidates as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
