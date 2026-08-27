<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use LogicException;
use PHPCfg\Script;
use PhpParser\Node;

/**
 * A successfully parsed file: the SSA control flow graph, the name-resolved
 * nikic AST it came from, and a source map for positions.
 *
 * Structural rules want the AST — matching `register_rest_route()`'s options
 * array is a shape question, not a dataflow question, and the AST states that
 * shape directly. Taint analysis wants the CFG. Keeping both avoids parsing
 * twice.
 *
 * The AST is released as soon as the structural rules have run. Analysis is
 * whole-program, so every file's state is held simultaneously, and the AST is
 * comparable in size to the CFG — holding both for the duration is what pushed
 * a five-plugin scan past a gigabyte.
 */
final class ParsedFile
{
    /** @var list<Node>|null */
    private ?array $ast;

    /**
     * @param list<Node>         $ast
     * @param array<string, int> $lowered constructs {@see CompatibilityVisitor} rewrote, and how many of each
     */
    public function __construct(
        public readonly string $path,
        public readonly string $relativePath,
        public readonly Script $script,
        array $ast,
        public readonly SourceMap $sourceMap,
        public readonly array $lowered = [],
    ) {
        $this->ast = $ast;
    }

    /**
     * @return list<Node>
     */
    public function ast(): array
    {
        if ($this->ast === null) {
            throw new LogicException(
                'The AST for ' . $this->relativePath . ' was released after the structural rules ran. '
                    . 'Anything that needs it must run before releaseAst().',
            );
        }

        return $this->ast;
    }

    public function releaseAst(): void
    {
        $this->ast = null;
    }
}
