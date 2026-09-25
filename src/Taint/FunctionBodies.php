<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ParsedFile;
use LogicException;
use PHPCfg\Func;

/**
 * Hands out the body of a function: the control flow graph its analysis runs
 * on, found from its {@see FunctionMeta}.
 *
 * It holds parsed files up to a memory budget and rebuilds any other file from
 * source, with the same {@see CfgBuilder}, when one of its functions is needed.
 * Building the same file again produces the same graph, and nothing that
 * outlives one analysis is keyed by a graph object, so a rebuilt body analyses
 * exactly as the original did. See docs/design/two-pass-engine.md.
 *
 * - No budget holds every file it is given, and rebuilds nothing.
 * - A budget of zero holds nothing and rebuilds on every request. That is for
 *   tests, which use it to prove the claim above.
 * - Any other budget admits files until the budget is full, then admits no
 *   more: a file it does not hold is rebuilt, used and dropped. The scan reads
 *   files in repeated sweeps, and for that pattern keeping what is already held
 *   beats evicting the least recently used by about half.
 */
final class FunctionBodies
{
    /** @var array<string, ParsedFile> absolute path => file */
    private array $files = [];

    /** @var array<string, array<int|string, FunctionContext>> path => position => context */
    private array $contexts = [];

    /** Heap the held files take, as measured when each was built or added. */
    private int $held = 0;

    private int $rebuilds = 0;

    /** The last file rebuilt and not admitted, kept until another is needed. */
    private ?ParsedFile $transient = null;

    public function __construct(
        private readonly ?CfgBuilder $builder = null,
        private readonly ?int $budget = null,
    ) {
    }

    /**
     * Offer a file that has just been built. `$size` is the heap it takes.
     */
    public function add(ParsedFile $file, int $size = 0): void
    {
        if ($this->budget === null) {
            $this->files[$file->path] = $file;

            return;
        }

        $this->admit($file, $size);
    }

    public function context(FunctionMeta $meta): FunctionContext
    {
        $slot = $meta->position ?? 'main';

        if (isset($this->contexts[$meta->path][$slot])) {
            return $this->contexts[$meta->path][$slot];
        }

        $file = $this->file($meta);
        $func = $meta->position === null
            ? $file->script->main
            : (array_values($file->script->functions)[$meta->position] ?? null);

        if (! $func instanceof Func) {
            throw new LogicException('No function at position ' . $meta->position . ' of ' . $meta->relativePath . '.');
        }

        $context = FunctionContext::create($func, $file);

        if (isset($this->files[$meta->path])) {
            $this->contexts[$meta->path][$slot] = $context;
        }

        return $context;
    }

    /**
     * Every body, in the order the metadata lists them.
     *
     * @param list<FunctionMeta> $metas
     *
     * @return list<FunctionContext>
     */
    public function contexts(array $metas): array
    {
        return array_map($this->context(...), $metas);
    }

    /**
     * How many files have been rebuilt from source.
     */
    public function rebuilds(): int
    {
        return $this->rebuilds;
    }

    /**
     * Heap the held files take.
     */
    public function held(): int
    {
        return $this->held;
    }

    private function file(FunctionMeta $meta): ParsedFile
    {
        $held = $this->files[$meta->path] ?? null;

        if ($held !== null) {
            return $held;
        }

        if ($this->budget !== 0 && $this->transient?->path === $meta->path) {
            return $this->transient;
        }

        if ($this->builder === null) {
            throw new LogicException('No body is held for ' . $meta->relativePath . ' and nothing can rebuild it.');
        }

        $before = memory_get_usage();
        $result = $this->builder->buildFromFile($meta->path);

        // It parsed the first time, and the same source parses the same way.
        if (! $result->isSuccess()) {
            throw new LogicException($meta->relativePath . ' parsed once and then failed to rebuild.');
        }

        $file = $result->file();
        $file->releaseAst();
        $this->rebuilds++;

        if (! $this->admit($file, max(0, memory_get_usage() - $before))) {
            $this->transient = $this->budget === 0 ? null : $file;
        }

        return $file;
    }

    private function admit(ParsedFile $file, int $size): bool
    {
        if ($this->budget === null || ($this->budget > 0 && $this->held + $size <= $this->budget)) {
            $this->files[$file->path] = $file;
            $this->held += $size;

            return true;
        }

        return false;
    }
}
