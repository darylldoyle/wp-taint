<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Support\CycleCollector;
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
 *
 * ## The pool
 *
 * An eighth of the budget is kept back for a pool, and the cache admits up to
 * the rest. The fixed point analyses a function's bodies together, and a
 * function declared in several files, a library several plugins each bundle,
 * has a body in each of them. With one transient file, every body of every
 * method of such a class rebuilt its file, twice: a class of m methods copied
 * into k uncached files cost 2km rebuilds a round where k would do. On a site
 * with 168 reference trees, three bundled copies of one PDF library cost 55 to 94
 * seconds a method, for hundreds of methods.
 *
 * So while the resolver works through one file's functions, every file rebuilt
 * for them stays in the pool, and the pool empties when the resolver moves to
 * the next file; see {@see retainFor()}. Nothing is evicted inside that run.
 * Least recently used would not do: the resolver cycles through the same k
 * files for each method, and once k files outgrow the pool, it would miss
 * every one. A file that does not fit the pool is rebuilt as before. Where a
 * body comes from never changes what it analyses to, so the pool changes time
 * and nothing else.
 */
final class FunctionBodies
{
    /** @var array<string, ParsedFile> absolute path => file */
    private array $files = [];

    /** @var array<string, array<int|string, FunctionContext>> path => position => context */
    private array $contexts = [];

    /** @var array<string, int> absolute path => its estimated size when last counted */
    private array $sizes = [];

    /** Heap the held files take, as {@see estimatedSize()} estimates it. */
    private int $held = 0;

    private int $rebuilds = 0;

    /** The last file rebuilt and not admitted, kept until another is needed. */
    private ?ParsedFile $transient = null;

    /** @var array<string, ParsedFile> absolute path => file rebuilt for the current owner */
    private array $pool = [];

    /** Heap the pooled files take, as {@see estimatedSize()} estimates it. */
    private int $pooled = 0;

    /** The file whose functions the pool is serving, or null when there is no pool. */
    private ?string $poolOwner = null;

    /** Bytes the cache may admit: the budget less the pool's share. */
    private readonly ?int $cacheBudget;

    /** Bytes the pool may hold. */
    private readonly int $poolBudget;

    public function __construct(
        private readonly ?CfgBuilder $builder = null,
        private readonly ?int $budget = null,
        /**
         * Ticked each time a file arrives or a body is handed out, which is
         * between two units of the scan's work in every phase.
         */
        private readonly ?CycleCollector $collector = null,
    ) {
        // No budget holds everything and needs no pool. A budget of zero
        // rebuilds on every request, which is what the tests rely on, so it
        // gets no pool either.
        $this->poolBudget = $budget === null || $budget === 0 ? 0 : intdiv($budget, 8);
        $this->cacheBudget = $budget === null ? null : $budget - $this->poolBudget;
    }

    /**
     * Serve the functions of this file next, keeping every file rebuilt for
     * them until the owner changes. Null empties the pool and stops using it.
     */
    public function retainFor(?string $owner): void
    {
        if ($owner === $this->poolOwner) {
            return;
        }

        foreach (array_keys($this->pool) as $path) {
            unset($this->contexts[$path]);
        }

        $this->pool = [];
        $this->pooled = 0;
        $this->poolOwner = $owner;
    }

    /**
     * Offer a file that has just been built.
     */
    public function add(ParsedFile $file): void
    {
        $this->collector?->tick();
        $this->admit($file, self::estimatedSize($file));
    }

    public function context(FunctionMeta $meta): FunctionContext
    {
        $this->collector?->tick();
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

        // Kept for as long as the file is, so a file with hundreds of methods
        // does not list its functions again for every one of them.
        if (isset($this->files[$meta->path]) || isset($this->pool[$meta->path])) {
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
     * A file with its AST, for the structural rules, which read the syntax.
     *
     * The held file when it still has one; otherwise rebuilt, used and
     * dropped, never admitted, because nothing else needs the AST.
     */
    public function fileWithAst(string $path): ParsedFile
    {
        $this->collector?->tick();
        $held = $this->files[$path] ?? null;

        if ($held !== null && $held->hasAst()) {
            return $held;
        }

        if ($this->builder === null) {
            throw new LogicException('No file with its AST is held for ' . $path . ' and nothing can rebuild it.');
        }

        $result = $this->builder->buildFromFile($path);

        if (! $result->isSuccess()) {
            throw new LogicException($path . ' parsed once and then failed to rebuild.');
        }

        $this->rebuilds++;

        return $result->file();
    }

    /**
     * Drop a held file's AST, once nothing will read it again.
     */
    public function releaseAst(string $path): void
    {
        $file = $this->files[$path] ?? null;

        if ($file === null || ! $file->hasAst()) {
            return;
        }

        $file->releaseAst();

        // The file now takes less, and the room it gave back is the budget's
        // again. Counting it at its size with the AST left most of a cache
        // filled during parsing empty for the rest of the scan.
        $size = self::estimatedSize($file);
        $this->held -= ($this->sizes[$path] ?? 0) - $size;
        $this->sizes[$path] = $size;
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

    /**
     * Heap the pooled files take.
     */
    public function pooled(): int
    {
        return $this->pooled;
    }

    /**
     * Bytes the pool may hold.
     */
    public function poolBudget(): int
    {
        return $this->poolBudget;
    }

    private function file(FunctionMeta $meta): ParsedFile
    {
        $held = $this->files[$meta->path] ?? null;

        if ($held !== null) {
            return $held;
        }

        $pooled = $this->pool[$meta->path] ?? null;

        if ($pooled !== null) {
            return $pooled;
        }

        if ($this->budget !== 0 && $this->transient?->path === $meta->path) {
            return $this->transient;
        }

        if ($this->builder === null) {
            throw new LogicException('No body is held for ' . $meta->relativePath . ' and nothing can rebuild it.');
        }

        $result = $this->builder->buildFromFile($meta->path);

        // It parsed the first time, and the same source parses the same way.
        if (! $result->isSuccess()) {
            throw new LogicException($meta->relativePath . ' parsed once and then failed to rebuild.');
        }

        $file = $result->file();
        $file->releaseAst();
        $this->rebuilds++;
        $size = self::estimatedSize($file);

        if ($this->admit($file, $size)) {
            return $file;
        }

        if ($this->poolOwner !== null && $this->pooled + $size <= $this->poolBudget) {
            $this->pool[$file->path] = $file;
            $this->pooled += $size;

            return $file;
        }

        $this->transient = $this->budget === 0 ? null : $file;

        return $file;
    }

    /**
     * The heap a parsed file holds, estimated from its source.
     *
     * Estimated rather than measured. The difference in heap usage around a
     * build includes whatever the garbage collector frees during it, which
     * makes a file come out small or negative, and a file measured at nothing
     * is admitted however full the cache is: that let a 512MB cache hold more
     * than a gigabyte. Turning the collector off for the build is worse, since
     * cycles that arrive while it is off can never be collected. The factors
     * are measured: across one 17-tree configuration's 19,008 files, a
     * graph with its AST released holds about 60 times its source, and the AST
     * adds about as much again as 40 of those.
     */
    public static function estimatedSize(ParsedFile $file): int
    {
        $source = @filesize($file->path);

        return ($source === false ? 0 : $source) * ($file->hasAst() ? 100 : 60);
    }

    private function admit(ParsedFile $file, int $size): bool
    {
        if ($this->cacheBudget === null || ($this->cacheBudget > 0 && $this->held + $size <= $this->cacheBudget)) {
            $this->files[$file->path] = $file;
            $this->sizes[$file->path] = $size;
            $this->held += $size;

            return true;
        }

        return false;
    }
}
