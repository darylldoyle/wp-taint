<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Decides whether an operand is "effectively literal" — safe to use as a
 * `$wpdb->prepare()` format string.
 *
 * A string literal is effectively literal. So is a concatenation of literals.
 * So, crucially, is a concatenation that interpolates `$wpdb->prefix` or any
 * other `wpdb` table property: that is the standard WordPress idiom, and
 * flagging it would produce a false positive on essentially every plugin.
 *
 * Anything else is not, and prepare() cannot protect it.
 */
final class LiteralAnalyzer
{
    public function __construct(private readonly Registry $registry)
    {
    }

    public function isEffectivelyLiteral(Operand $operand): bool
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();

        return $this->check($operand, $seen, 0);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function check(Operand $operand, SplObjectStorage $seen, int $depth): bool
    {
        if ($depth > 32 || $seen->contains($operand)) {
            return false;
        }

        $seen->attach($operand);

        if ($operand instanceof Operand\Literal) {
            return true;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            return false;
        }

        if ($definition instanceof Op\Expr\BinaryOp\Concat) {
            return $this->check($definition->left, $seen, $depth + 1)
                && $this->check($definition->right, $seen, $depth + 1);
        }

        if ($definition instanceof Op\Expr\ConcatList) {
            foreach ($definition->list as $item) {
                if (! $item instanceof Operand || ! $this->check($item, $seen, $depth + 1)) {
                    return false;
                }
            }

            return true;
        }

        if ($definition instanceof Op\Expr\Assign) {
            return $this->check($definition->expr, $seen, $depth + 1);
        }

        if ($definition instanceof Op\Expr\ConstFetch || $definition instanceof Op\Expr\ClassConstFetch) {
            // A constant cannot be influenced by a request.
            return true;
        }

        if ($definition instanceof Op\Expr\PropertyFetch) {
            return $this->isSafeDatabaseIdentifier($definition);
        }

        return false;
    }

    /**
     * `{$wpdb->prefix}`, `{$wpdb->posts}` and the rest of the table-name
     * properties.
     */
    private function isSafeDatabaseIdentifier(Op\Expr\PropertyFetch $fetch): bool
    {
        $property = OperandHelper::literalString($fetch->name);

        if ($property === null) {
            return false;
        }

        if (! in_array($property, $this->registry->safeDatabaseIdentifiers(), true)) {
            return false;
        }

        $receiver = OperandHelper::variableName($fetch->var);

        if ($receiver !== null) {
            return strtolower($receiver) === 'wpdb';
        }

        // `$this->wpdb->prefix`.
        $definition = OperandHelper::definingOp($fetch->var);

        if (! $definition instanceof Op\Expr\PropertyFetch) {
            return false;
        }

        $name = OperandHelper::literalString($definition->name);

        return $name !== null && in_array(strtolower($name), ['wpdb', 'db'], true);
    }
}
