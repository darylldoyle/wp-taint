<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

/**
 * Expands the paths given on the command line into a sorted list of PHP files.
 *
 * Sorted, because file order determines which duplicate function declaration
 * wins and therefore has to be stable across machines.
 */
final class FileFinder
{
    private const DEFAULT_EXCLUDES = [
        '*/vendor/*',
        '*/node_modules/*',
        '*/.git/*',
    ];

    /** @var list<string> */
    private readonly array $excludes;

    /**
     * @param list<string> $excludes glob patterns, matched against the absolute path
     */
    public function __construct(array $excludes = [], bool $useDefaultExcludes = true)
    {
        $this->excludes = $useDefaultExcludes
            ? [...self::DEFAULT_EXCLUDES, ...$excludes]
            : $excludes;
    }

    /**
     * @param list<string> $paths
     *
     * @return list<string>
     */
    public function find(array $paths): array
    {
        $files = [];

        foreach ($paths as $path) {
            $real = realpath($path);

            if ($real === false) {
                throw new RuntimeException(sprintf('Path does not exist: %s', $path));
            }

            if (is_file($real)) {
                if ($this->accepts($real)) {
                    $files[$real] = true;
                }

                continue;
            }

            foreach ($this->walk($real) as $file) {
                $files[$file] = true;
            }
        }

        $result = array_keys($files);
        sort($result);

        return $result;
    }

    /**
     * @return list<string>
     */
    private function walk(string $directory): array
    {
        // CATCH_GET_CHILD: a directory we cannot read is skipped rather than
        // aborting the walk. A tree with one unreadable subdirectory in it is
        // still worth scanning, and the alternative is a scan that dies partway
        // through with an iterator exception.
        //
        // Unreadable directories are recorded and surfaced by the caller, so
        // this is a skip the user is told about rather than a silent one.
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD,
        );

        $files = [];

        foreach ($iterator as $info) {
            if (! $info instanceof SplFileInfo || ! $info->isFile()) {
                continue;
            }

            $path = $info->getPathname();

            if ($this->accepts($path)) {
                $files[] = $path;
            }
        }

        return $files;
    }

    private function accepts(string $path): bool
    {
        if (strtolower(pathinfo($path, PATHINFO_EXTENSION)) !== 'php') {
            return false;
        }

        $normalised = str_replace('\\', '/', $path);

        foreach ($this->excludes as $pattern) {
            if (fnmatch($pattern, $normalised) || fnmatch($pattern, basename($normalised))) {
                return false;
            }
        }

        return true;
    }
}
