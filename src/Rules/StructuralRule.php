<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Registry\Registry;

/**
 * A pattern check that is not a dataflow question.
 *
 * Broken authorization is arguably a larger share of real WordPress CVEs than
 * injection is, and taint analysis structurally cannot find it: there is no
 * source and no sink, only a missing check. These rules cover that.
 *
 * They run on the name-resolved nikic AST rather than the CFG, because the
 * questions they ask — "does this options array have a `permission_callback`
 * key" — are about syntactic shape, which the AST states directly and the CFG
 * has already dissolved.
 */
interface StructuralRule
{
    public function id(): string;

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array;
}
