<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * The shape check behind `wp.sqli.unprepared-query`.
 *
 * Taint analysis reports the flows it can follow. This reports the *shape* —
 * a variable interpolated into a query — which catches queries built from
 * values the dataflow engine could not reach: an unresolvable helper, a
 * dynamic call, a value from a file outside the scan.
 *
 * It has to be a dataflow question rather than a purely syntactic one, or it
 * becomes a noise machine. Both of these interpolate a variable:
 *
 *     $id = absint( $_GET['id'] );
 *     $wpdb->query( "DELETE FROM t WHERE id = {$id}" );           // safe
 *
 *     $order = some_helper_we_cannot_see();
 *     $wpdb->get_results( "SELECT * FROM t ORDER BY {$order}" );  // unknown
 *
 * The first is the most common safe idiom in the ecosystem, and flagging it
 * would bury every real finding. The difference is that its every contributor
 * is accounted for — a registry sanitizer applied to a known source — and the
 * second's is not.
 *
 * Two further restrictions keep it quiet:
 *
 * - The query must actually be *built* (a concatenation or an interpolation).
 *   A bare `$wpdb->query( $sql )` inside a helper is not reported here; the
 *   interprocedural summary reports its callers instead.
 * - `{$wpdb->prefix}` and the other table-name properties never count, because
 *   they are the standard idiom and are not attacker-controlled.
 */
final class QueryShapeInspector
{
    public function __construct(
        private readonly LiteralAnalyzer $literals,
        private readonly OriginClassifier $origins,
    ) {
    }

    /**
     * The first component of a built query string whose origin the engine
     * could not account for, or null when there is none.
     */
    public function unaccountedComponent(
        Operand $query,
        FunctionContext $context,
        ClassTypeMap $types,
    ): ?Operand {
        $components = $this->components($query);

        if ($components === null) {
            return null;
        }

        foreach ($components as $component) {
            if ($this->literals->isEffectivelyLiteral($component)) {
                continue;
            }

            if ($this->origins->isFullyResolved($component, $context, $types)) {
                continue;
            }

            return $component;
        }

        return null;
    }

    /**
     * The parts of a concatenated or interpolated string.
     *
     * Null when the operand is not a built string at all, which is how a bare
     * variable is excluded.
     *
     * @return list<Operand>|null
     */
    private function components(Operand $operand): ?array
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();
        $parts = [];

        return $this->collect($operand, $seen, $parts, 0) ? $parts : null;
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     * @param list<Operand>                   $parts
     */
    private function collect(Operand $operand, SplObjectStorage $seen, array &$parts, int $depth): bool
    {
        if ($depth > 24 || $seen->contains($operand)) {
            return false;
        }

        $seen->attach($operand);

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->collect($definition->expr, $seen, $parts, $depth + 1);
        }

        if ($definition instanceof Op\Expr\BinaryOp\Concat) {
            $this->addPart($definition->left, $seen, $parts, $depth);
            $this->addPart($definition->right, $seen, $parts, $depth);

            return true;
        }

        if ($definition instanceof Op\Expr\ConcatList) {
            foreach ($definition->list as $item) {
                if ($item instanceof Operand) {
                    $this->addPart($item, $seen, $parts, $depth);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     * @param list<Operand>                   $parts
     */
    private function addPart(Operand $operand, SplObjectStorage $seen, array &$parts, int $depth): void
    {
        // Flatten nested concatenations so `'a' . $b . 'c'` yields three parts
        // rather than a tree.
        $nested = [];

        if ($this->collect($operand, $seen, $nested, $depth + 1)) {
            $parts = [...$parts, ...$nested];

            return;
        }

        $parts[] = $operand;
    }
}
