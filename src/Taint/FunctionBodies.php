<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use LogicException;
use PHPCfg\Func;

/**
 * Hands out the body of a function: the control flow graph its analysis runs
 * on, found from its {@see FunctionMeta}.
 *
 * For now every parsed file is held, exactly as before, so this only changes
 * where a body is looked up. It is the one place that will later rebuild a
 * dropped file's graph from source under a memory budget; see
 * docs/design/two-pass-engine.md.
 */
final class FunctionBodies
{
    /** @var array<string, ParsedFile> absolute path => file */
    private array $files = [];

    /** @var array<string, array<int|string, FunctionContext>> path => position => context */
    private array $contexts = [];

    public function add(ParsedFile $file): void
    {
        $this->files[$file->path] = $file;
    }

    public function context(FunctionMeta $meta): FunctionContext
    {
        $slot = $meta->position ?? 'main';

        if (isset($this->contexts[$meta->path][$slot])) {
            return $this->contexts[$meta->path][$slot];
        }

        $file = $this->files[$meta->path] ?? null;

        if ($file === null) {
            throw new LogicException('No body is held for ' . $meta->relativePath . '.');
        }

        $func = $meta->position === null
            ? $file->script->main
            : (array_values($file->script->functions)[$meta->position] ?? null);

        if (! $func instanceof Func) {
            throw new LogicException('No function at position ' . $meta->position . ' of ' . $meta->relativePath . '.');
        }

        return $this->contexts[$meta->path][$slot] = FunctionContext::create($func, $file);
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
}
