<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Generator;
use IteratorAggregate;

/**
 * Every function's body, one after another, fetched as it is reached.
 *
 * What the setup builders iterate instead of a list of contexts held for the
 * whole scan. Each iteration is a sweep over the files: a body the
 * {@see FunctionBodies} provider does not hold is rebuilt when it is reached and
 * dropped when the sweep moves on. A file's functions are listed together, and
 * the provider keeps the last file it rebuilt, so a sweep rebuilds a file at
 * most once. It can be iterated as often as a builder needs:
 * {@see \Enshrined\WpTaint\Cfg\ConstantTableBuilder} makes two passes.
 *
 * @implements IteratorAggregate<int, FunctionContext>
 */
final class BodySweep implements IteratorAggregate
{
    /**
     * @param list<FunctionMeta> $functions
     */
    public function __construct(
        private readonly FunctionBodies $bodies,
        private readonly array $functions,
    ) {
    }

    /**
     * @return Generator<int, FunctionContext>
     */
    public function getIterator(): Generator
    {
        foreach ($this->functions as $index => $function) {
            yield $index => $this->bodies->context($function);
        }
    }
}
