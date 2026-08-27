<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Support;

/**
 * File paths in output are always relative to the scan root, so that findings
 * are portable between machines and diffable between runs.
 */
final class PathHelper
{
    public static function relative(string $path, string $root): string
    {
        $normalisedPath = self::normalise($path);
        $normalisedRoot = rtrim(self::normalise($root), '/');

        if ($normalisedRoot === '') {
            return $normalisedPath;
        }

        if (str_starts_with($normalisedPath, $normalisedRoot . '/')) {
            return substr($normalisedPath, strlen($normalisedRoot) + 1);
        }

        return $normalisedPath;
    }

    public static function normalise(string $path): string
    {
        $real = realpath($path);

        return str_replace('\\', '/', $real === false ? $path : $real);
    }

    /**
     * The deepest directory containing every given path, used as the scan root
     * when the user passes several paths.
     *
     * @param list<string> $paths
     */
    public static function commonRoot(array $paths): string
    {
        if ($paths === []) {
            return (string) getcwd();
        }

        $segmentLists = [];

        foreach ($paths as $path) {
            $normalised = self::normalise($path);
            $directory = is_dir($normalised) ? $normalised : dirname($normalised);
            $segmentLists[] = explode('/', trim($directory, '/'));
        }

        $common = array_shift($segmentLists);

        if ($common === null) {
            return (string) getcwd();
        }

        foreach ($segmentLists as $segments) {
            $length = min(count($common), count($segments));
            $shared = [];

            for ($i = 0; $i < $length; $i++) {
                $segment = $common[$i] ?? null;

                if ($segment === null || $segment !== ($segments[$i] ?? null)) {
                    break;
                }

                $shared[] = $segment;
            }

            $common = $shared;
        }

        return '/' . implode('/', $common);
    }
}
