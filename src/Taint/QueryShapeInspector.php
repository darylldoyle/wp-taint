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
        private readonly ?ValueResolver $values = null,
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
     * The first component interpolated *outside* any quotes, which no escaper
     * can make safe.
     *
     * ```php
     * $wpdb->get_row( "SELECT * FROM t WHERE ID = " . esc_sql( $id ) );
     * ```
     *
     * `esc_sql()` escapes quotes and backslashes. With no quotes around the
     * value there is nothing for it to escape, and `1 OR 1=1` reaches the
     * database intact. The same is true of `sanitize_text_field()` and every
     * other string sanitizer: they defend a quoted context and do nothing for
     * a bare one.
     *
     * The caller decides which components are at risk, and passes the only
     * answer that keeps this narrow: a value carrying
     * {@see TaintKind::SqlUnquoted}, meaning it was escaped for quotes it did
     * not get. A table name built by a helper method never carried SQL taint,
     * never picked the kind up, and is not reported — which matters, because
     * `"SELECT ... FROM {$table}"` appears hundreds of times in the corpus.
     *
     * This project shipped the opposite advice. `wp.sqli.wpdb-query` told
     * people "esc_sql() is acceptable but prepare() is preferred", which is
     * true inside quotes and dangerous outside them, and it took the WordPress
     * plugin team's own intentionally vulnerable plugin to point it out.
     */
    /**
     * @param callable(Operand): bool $atRisk
     */
    public function unquotedComponent(Operand $query, callable $atRisk): ?Operand
    {
        $components = $this->components($query);

        if ($components === null) {
            return null;
        }

        $inQuotes = false;

        foreach ($components as $component) {
            if ($component instanceof Operand\Literal && is_string($component->value)) {
                $inQuotes = self::quoteStateAfter($component->value, $inQuotes);

                continue;
            }

            if (! $inQuotes && $atRisk($component)) {
                return $component;
            }

            // A fragment that is not written as a literal may still *be* one —
            // a helper returning a constant clause, `"WHERE name = '"` built a
            // call away. Its text carries quote state like any other fragment,
            // and skipping it read the escaped value that follows as unquoted.
            // Only a fragment folding to exactly one string counts: two
            // possible texts could disagree about the state they leave behind.
            $folded = $this->values?->strings($component) ?? [];

            if (count($folded) === 1) {
                $inQuotes = self::quoteStateAfter($folded[0], $inQuotes);
            }
        }

        return null;
    }

    /**
     * The first component landing inside a quoted HTML attribute, which the
     * html-text escapers do not protect.
     *
     * The markup twin of {@see unquotedComponent}: literal fragments carry the
     * position, a fragment folding to exactly one string counts as its text,
     * and the caller decides which components are at risk — a value carrying
     * {@see TaintKind::HtmlAttr} without {@see TaintKind::Html}, meaning its
     * tags were stripped and its quotes were not.
     *
     * ```php
     * $safe = sanitize_text_field( $_GET['title'] );
     * echo '<input value="' . $safe . '">';   // " onmouseover=… x=" gets out
     * echo '<p>' . $safe . '</p>';            // nothing to get out of
     * ```
     *
     * A hole that is not the risky component still advances the scan as
     * unknown text, and a position inside a <script> block is left to the
     * script rules.
     */
    /**
     * @param callable(Operand): bool $atRisk
     */
    public function quotedAttributeComponent(Operand $output, callable $atRisk): ?Operand
    {
        $components = $this->components($output);

        if ($components === null) {
            return null;
        }

        $before = '';

        foreach ($components as $component) {
            if ($component instanceof Operand\Literal && is_string($component->value)) {
                $before .= $component->value;

                continue;
            }

            if ($atRisk($component) && ! MarkupPosition::inScript($before)) {
                $attribute = MarkupPosition::openAttribute($before);

                if ($attribute !== null && $attribute[1] !== null) {
                    return $component;
                }
            }

            $folded = $this->values?->strings($component) ?? [];
            $before .= count($folded) === 1 ? $folded[0] : 'x';
        }

        return null;
    }

    /**
     * Whether a run of SQL text leaves us inside a string literal.
     *
     * Only single and double quotes, and only unescaped ones. Backticks quote
     * identifiers rather than values and offer no protection to a value, so
     * they deliberately do not count as being "in quotes".
     */
    private static function quoteStateAfter(string $text, bool $inQuotes): bool
    {
        $quote = null;
        $length = strlen($text);

        for ($index = 0; $index < $length; $index++) {
            $character = $text[$index];

            if ($character === '\\') {
                $index++;

                continue;
            }

            if ($character !== "'" && $character !== '"') {
                continue;
            }

            if ($quote === null && ! $inQuotes) {
                $quote = $character;
                $inQuotes = true;

                continue;
            }

            if ($character === $quote || $quote === null) {
                $quote = null;
                $inQuotes = false;
            }
        }

        return $inQuotes;
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
