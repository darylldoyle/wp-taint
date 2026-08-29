<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Registry\RegistryException;
use Throwable;
use Yosymfony\Toml\Toml;

/**
 * The `[scan]` section of a project's `wp-taint.toml`.
 *
 * ## What it is for
 *
 * A real WordPress checkout is mostly code you did not write. The interesting
 * shape is a handful of first-party directories inside an install of thousands
 * of third-party files, and often those directories reference each other — a
 * client platform plugin and the two themes built against it are one program,
 * not three scans.
 *
 * That is already expressible on the command line: several paths analysed
 * together, `--include-path` for trees that supply symbols but never findings.
 * It is just long enough that nobody types it twice.
 *
 * ```toml
 * [scan]
 * paths = [
 *     "wp-content/mu-plugins/client-platform",
 *     "wp-content/themes/client-theme",
 * ]
 * reference = ["wp-content/plugins/some-dependency"]
 * exclude = ["*&#47;vendor/*"]
 *
 * [scan.options]
 * jobs = 4
 * fail_on = "high"
 * ```
 *
 * `paths` are analysed together as one program and reported on. `reference` is
 * parsed for symbols and never reported on — the same split PHPStan draws
 * between `paths` and `scanDirectories`.
 *
 * ## Do not reference WordPress core here
 *
 * Measured on a real client theme: 310 files scan in 1.8 seconds alone, 163
 * seconds with `wp-includes` referenced, and the ten extra findings were all
 * false positives from core's block-template machinery tainting
 * `$template->content` and the theme echoing rendered block content. The
 * catalogue already models the core functions that matter. Reference a specific
 * third-party plugin when your code genuinely calls into it, and nothing else.
 *
 * ## Precedence
 *
 * Anything given on the command line wins. Paths given as arguments replace the
 * configured ones outright rather than adding to them, because a developer
 * naming one directory means to scan that directory.
 */
final class ProjectScanConfig
{
    private const KEYS = ['paths', 'reference', 'bootstrap', 'exclude', 'options'];

    private const OPTION_KEYS = ['jobs', 'fail_on', 'min_severity', 'format', 'baseline', 'stored_taint_writes'];

    /**
     * @param list<string> $paths
     * @param list<string> $reference
     * @param list<string> $bootstrap
     * @param list<string> $excludes
     */
    private function __construct(
        public readonly array $paths,
        public readonly array $reference,
        /**
         * Files parsed for the constants and symbols they define, never
         * reported on. The PHPStan/PHPUnit bootstrap idea, and mechanically the
         * same thing as `reference`: it exists as its own key because "where do
         * I put the `define( 'ABSPATH', … )` the scan cannot otherwise see" is
         * a question with a name.
         *
         *     [scan]
         *     bootstrap = ["wp-taint-bootstrap.php"]
         */
        public readonly array $bootstrap,
        public readonly array $excludes,
        public readonly ?int $jobs,
        public readonly ?string $failOn,
        public readonly ?string $minimumSeverity,
        public readonly ?string $format,
        public readonly ?string $baseline,
        public readonly ?bool $storedTaintWrites,
    ) {
    }

    public static function empty(): self
    {
        return new self([], [], [], [], null, null, null, null, null, null);
    }

    /**
     * Read `[scan]` from a `wp-taint.toml`, resolving paths against its own
     * directory so the file works from anywhere.
     */
    public static function load(string $file): self
    {
        $contents = file_get_contents($file);

        if ($contents === false) {
            throw new RegistryException(sprintf('Unable to read config file: %s', $file));
        }

        try {
            $parsed = Toml::parse($contents);
        } catch (Throwable $error) {
            throw new RegistryException(sprintf('%s: malformed TOML — %s', $file, $error->getMessage()));
        }

        if (! is_array($parsed)) {
            throw new RegistryException(sprintf('%s: expected a TOML table at the top level.', $file));
        }

        $scan = $parsed['scan'] ?? null;

        if ($scan === null) {
            return self::empty();
        }

        if (! is_array($scan)) {
            throw new RegistryException(sprintf('%s: [scan] must be a table.', $file));
        }

        self::rejectUnknownKeys($file, '[scan]', $scan, self::KEYS);

        $options = $scan['options'] ?? [];

        if (! is_array($options)) {
            throw new RegistryException(sprintf('%s: [scan.options] must be a table.', $file));
        }

        self::rejectUnknownKeys($file, '[scan.options]', $options, self::OPTION_KEYS);

        $resolved = realpath($file);
        $root = dirname($resolved === false ? $file : $resolved);

        return new self(
            self::paths($file, 'paths', $scan['paths'] ?? [], $root),
            self::paths($file, 'reference', $scan['reference'] ?? [], $root),
            self::paths($file, 'bootstrap', $scan['bootstrap'] ?? [], $root),
            self::strings($file, 'exclude', $scan['exclude'] ?? []),
            self::integer($file, 'jobs', $options['jobs'] ?? null),
            self::text($file, 'fail_on', $options['fail_on'] ?? null),
            self::text($file, 'min_severity', $options['min_severity'] ?? null),
            self::text($file, 'format', $options['format'] ?? null),
            ($baseline = self::text($file, 'baseline', $options['baseline'] ?? null)) === null
                ? null
                : self::resolve($baseline, $root),
            self::flag($file, 'stored_taint_writes', $options['stored_taint_writes'] ?? null),
        );
    }

    /**
     * The nearest `wp-taint.toml` at or above the working directory.
     *
     * Walking upward so `wp-taint scan` works from inside the theme you are
     * editing, not only from the WordPress root where the file lives.
     */
    public static function discover(string $from): ?string
    {
        $resolved = realpath($from);
        $directory = $resolved === false ? $from : $resolved;

        // A file argument: start from the directory holding it.
        if (is_file($directory)) {
            $directory = dirname($directory);
        }

        while (true) {
            $candidate = $directory . '/wp-taint.toml';

            if (is_file($candidate)) {
                return $candidate;
            }

            $parent = dirname($directory);

            if ($parent === $directory) {
                return null;
            }

            $directory = $parent;
        }
    }

    /**
     * @param array<array-key, mixed> $table
     * @param list<string>            $allowed
     */
    private static function rejectUnknownKeys(string $file, string $context, array $table, array $allowed): void
    {
        foreach (array_keys($table) as $key) {
            if (! in_array((string) $key, $allowed, true)) {
                throw new RegistryException(sprintf(
                    '%s: unknown key "%s" in %s. Known keys: %s.',
                    $file,
                    (string) $key,
                    $context,
                    implode(', ', $allowed),
                ));
            }
        }
    }

    /**
     * @return list<string>
     */
    private static function paths(string $file, string $key, mixed $value, string $root): array
    {
        return array_map(
            static fn (string $path): string => self::resolve($path, $root),
            self::strings($file, $key, $value),
        );
    }

    private static function resolve(string $path, string $root): string
    {
        return str_starts_with($path, '/') ? rtrim($path, '/') : rtrim($root . '/' . $path, '/');
    }

    private static function text(string $file, string $key, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new RegistryException(sprintf('%s: [scan.options] %s must be a string.', $file, $key));
        }

        return $value;
    }

    private static function integer(string $file, string $key, mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        if (! is_int($value)) {
            throw new RegistryException(sprintf('%s: [scan.options] %s must be an integer.', $file, $key));
        }

        return $value;
    }

    private static function flag(string $file, string $key, mixed $value): ?bool
    {
        if ($value === null) {
            return null;
        }

        if (! is_bool($value)) {
            throw new RegistryException(sprintf('%s: [scan.options] %s must be true or false.', $file, $key));
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function strings(string $file, string $key, mixed $value): array
    {
        if (! is_array($value)) {
            throw new RegistryException(sprintf('%s: [scan] %s must be an array of strings.', $file, $key));
        }

        $out = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new RegistryException(sprintf('%s: [scan] %s must contain only strings.', $file, $key));
            }

            $out[] = $item;
        }

        return $out;
    }
}
