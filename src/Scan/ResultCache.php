<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use Throwable;

/**
 * A content-addressed cache of whole scan results.
 *
 * Storing the result rather than intermediate state keeps the cache impossible
 * to invalidate incorrectly: the key covers every input, so a hit is a hit on
 * an identical scan and a miss costs only the hashing.
 *
 * `durationMs` is preserved from the original run rather than being re-measured,
 * so a cached result stays byte-identical to the one it replaces. The cache
 * lookup time is reported separately by the caller.
 */
final class ResultCache
{
    public function __construct(private readonly string $directory)
    {
    }

    /**
     * @param list<string> $files
     */
    public function key(array $files, string $fingerprint): string
    {
        $material = $fingerprint;

        foreach ($files as $file) {
            $hash = is_readable($file) ? md5_file($file) : false;
            $material .= "\0" . $file . "\0" . ($hash === false ? 'unreadable' : $hash);
        }

        return hash('sha256', $material);
    }

    public function get(string $key): ?ScanResult
    {
        $path = $this->pathFor($key);

        if (! is_file($path)) {
            return null;
        }

        $contents = is_readable($path) ? file_get_contents($path) : false;

        if ($contents === false) {
            return null;
        }

        try {
            $result = unserialize($contents, ['allowed_classes' => true]);
        } catch (Throwable) {
            // A cache written by an incompatible build. Treat as a miss and let
            // it be overwritten; never let a stale cache produce a wrong answer.
            return null;
        }

        return $result instanceof ScanResult ? $result : null;
    }

    public function put(string $key, ScanResult $result): void
    {
        if (! is_dir($this->directory) && ! @mkdir($this->directory, 0o755, true) && ! is_dir($this->directory)) {
            return;
        }

        $path = $this->pathFor($key);
        $temporary = $path . '.' . getmypid() . '.tmp';

        if (@file_put_contents($temporary, serialize($result)) === false) {
            return;
        }

        // Atomic replace, so a concurrent reader never sees a half-written file.
        if (! @rename($temporary, $path)) {
            @unlink($temporary);
        }
    }

    public function clear(): void
    {
        $entries = glob($this->directory . '/*.cache');

        foreach ($entries === false ? [] : $entries as $entry) {
            @unlink($entry);
        }
    }

    private function pathFor(string $key): string
    {
        return $this->directory . '/' . $key . '.cache';
    }
}
