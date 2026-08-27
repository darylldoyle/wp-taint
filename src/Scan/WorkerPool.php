<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Scan;

use RuntimeException;
use Throwable;

/**
 * Runs a shard of work across forked child processes.
 *
 * The fork happens **after** parsing, so children inherit every parsed CFG
 * through copy-on-write rather than re-reading the tree. That is the whole
 * reason this is worth doing: parsing is serial and cheap relative to the
 * analysis, and the analysis is what parallelises.
 *
 * Results come back through temporary files rather than pipes, because a
 * summary set for a large plugin comfortably exceeds the platform pipe buffer
 * and a blocked writer would deadlock against a parent that is still forking.
 *
 * Shards are merged in shard order, never in completion order, so the output is
 * identical whatever the scheduler does. That is not a nicety: `--jobs=8` and
 * `--jobs=1` are required to produce byte-identical results, and a scanner
 * whose answer depends on core count is a scanner nobody can baseline.
 */
final class WorkerPool
{
    public function __construct(private readonly int $jobs)
    {
    }

    public static function isSupported(): bool
    {
        return function_exists('pcntl_fork')
            && function_exists('pcntl_waitpid')
            && function_exists('posix_kill');
    }

    /**
     * Run `$work` once per shard and return the results in shard order.
     *
     * @template T
     *
     * @param callable(int, int): T $work shard index, shard count
     *
     * @return list<T>
     */
    public function run(callable $work): array
    {
        if ($this->jobs < 2 || ! self::isSupported()) {
            return [$work(0, 1)];
        }

        $directory = $this->makeTemporaryDirectory();

        try {
            return $this->fork($work, $directory);
        } finally {
            $this->removeDirectory($directory);
        }
    }

    /**
     * @template T
     *
     * @param callable(int, int): T $work
     *
     * @return list<T>
     */
    private function fork(callable $work, string $directory): array
    {
        /** @var array<int, int> $children pid => shard */
        $children = [];

        for ($shard = 0; $shard < $this->jobs; $shard++) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                // Out of processes. Reap what we have and fall back to running
                // the rest here rather than failing the scan.
                $this->reap($children);

                return [$work(0, 1)];
            }

            if ($pid === 0) {
                $this->runChild($work, $shard, $directory);
            }

            $children[$pid] = $shard;
        }

        $failed = $this->reap($children);

        if ($failed !== []) {
            throw new RuntimeException(sprintf(
                'Worker process%s %s exited abnormally. Re-run with --jobs=1.',
                count($failed) === 1 ? '' : 'es',
                implode(', ', $failed),
            ));
        }

        $results = [];

        for ($shard = 0; $shard < $this->jobs; $shard++) {
            $results[] = $this->readShard($directory, $shard);
        }

        return $results;
    }

    /**
     * @param callable(int, int): mixed $work
     */
    private function runChild(callable $work, int $shard, string $directory): never
    {
        $status = 0;

        try {
            $payload = serialize($work($shard, $this->jobs));

            if (file_put_contents($directory . '/' . $shard . '.result', $payload) === false) {
                $status = 1;
            }
        } catch (Throwable $error) {
            file_put_contents($directory . '/' . $shard . '.error', $error->getMessage());
            $status = 1;
        }

        // exit() rather than a return: the child shares the parent's open
        // handles and object destructors, and running them twice is not safe.
        exit($status);
    }

    /**
     * @param array<int, int> $children pid => shard
     *
     * @return list<int> shards that failed
     */
    private function reap(array $children): array
    {
        $failed = [];

        foreach ($children as $pid => $shard) {
            $status = 0;
            pcntl_waitpid($pid, $status);

            $code = is_int($status) ? $status : 0;

            if (! pcntl_wifexited($code) || pcntl_wexitstatus($code) !== 0) {
                $failed[] = $shard;
            }
        }

        sort($failed);

        return $failed;
    }

    private function readShard(string $directory, int $shard): mixed
    {
        $path = $directory . '/' . $shard . '.result';

        if (! is_file($path)) {
            throw new RuntimeException(sprintf('Worker %d produced no result. Re-run with --jobs=1.', $shard));
        }

        $payload = file_get_contents($path);

        if ($payload === false) {
            throw new RuntimeException(sprintf('Worker %d result could not be read. Re-run with --jobs=1.', $shard));
        }

        return unserialize($payload, ['allowed_classes' => true]);
    }

    private function makeTemporaryDirectory(): string
    {
        $directory = sys_get_temp_dir() . '/wp-taint-jobs-' . getmypid() . '-' . bin2hex(random_bytes(6));

        if (! mkdir($directory, 0o700, true) && ! is_dir($directory)) {
            throw new RuntimeException('Unable to create a working directory for --jobs.');
        }

        return $directory;
    }

    private function removeDirectory(string $directory): void
    {
        $files = glob($directory . '/*');

        foreach ($files === false ? [] : $files as $file) {
            @unlink($file);
        }

        @rmdir($directory);
    }
}
