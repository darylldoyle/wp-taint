<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

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
 */
final class ParsedFile
{
    /**
     * @param list<Node>           $ast
     * @param array<string, int>   $lowered constructs {@see CompatibilityVisitor} rewrote, and how many of each
     */
    public function __construct(
        public readonly string $path,
        public readonly string $relativePath,
        public readonly Script $script,
        public readonly array $ast,
        public readonly SourceMap $sourceMap,
        public readonly array $lowered = [],
    ) {
    }
}
