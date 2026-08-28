<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Decides whether an operand is "effectively literal" — safe to use as a
 * `$wpdb->prepare()` format string.
 *
 * The bar is not "is a string literal". It is **"cannot carry attacker-supplied
 * SQL syntax"**, which is what prepare() actually needs from its format string.
 * Three things clear that bar:
 *
 * 1. Literals, constants, and concatenations of them.
 * 2. Any property read on `$wpdb`. `$wpdb->prefix` and the core table names are
 *    the obvious case, but plugins register their own — Action Scheduler adds
 *    `$wpdb->actionscheduler_actions`, and WooCommerce interpolates it into
 *    fourteen prepared queries. Nothing attacker-controlled reaches a property
 *    of the global database handle, and the map is consulted anyway so a
 *    property that somehow *did* carry taint is still reported.
 * 3. Values built only from the above through calls the catalogue models as
 *    pure — which is what makes the canonical `IN (...)` placeholder idiom
 *    work:
 *
 *    ```php
 *    $placeholders = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );
 *    $wpdb->query( $wpdb->prepare( "... WHERE id IN ( {$placeholders} )", $ids ) );
 *    ```
 *
 *    Every character of `$placeholders` came from the literals `', '` and
 *    `'%d'`; only its *length* depends on the data. Treating that as
 *    non-literal produced false positives on Akismet and All in One SEO on the
 *    first corpus run, and it is the recommended way to write a prepared
 *    `IN (...)` clause.
 *
 * An integer is also effectively literal: `absint( $_GET['id'] )` cannot inject
 * SQL syntax however it is interpolated. So is the output of an inner
 * `$wpdb->prepare()`, which is how a WHERE clause gets assembled from prepared
 * fragments:
 *
 * ```php
 * foreach ( $types as $type ) {
 *     $where .= $wpdb->prepare( ' AND comment_type <> %s ', $type );
 * }
 * $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->comments} WHERE x = %d" . $where, $id ) );
 * ```
 *
 * Anything else is not, and prepare() cannot protect it.
 */
final class LiteralAnalyzer
{
    private const MAX_DEPTH = 32;

    public function __construct(
        private readonly Registry $registry,
        private readonly PropertyTaintMap $properties,
    ) {
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
        if ($depth > self::MAX_DEPTH) {
            return false;
        }

        // A cycle is a loop-carried value; by the time we come back round to it
        // every contributor has already been checked.
        if ($seen->contains($operand)) {
            return true;
        }

        $seen->attach($operand);

        if ($operand instanceof Operand\Literal) {
            return true;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            return false;
        }

        return $this->checkOp($definition, $seen, $depth);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function checkOp(Op $definition, SplObjectStorage $seen, int $depth): bool
    {
        $recurse = fn (Operand $next): bool => $this->check($next, $seen, $depth + 1);

        return match (true) {
            $definition instanceof Op\Expr\ConstFetch,
            $definition instanceof Op\Expr\ClassConstFetch => true,
            // An integer or float cannot carry SQL syntax, whatever it came from.
            $definition instanceof Op\Expr\Cast\Int_,
            $definition instanceof Op\Expr\Cast\Double,
            $definition instanceof Op\Expr\Cast\Bool_ => true,
            $definition instanceof Op\Expr\Assign,
            $definition instanceof Op\Expr\AssignRef => $recurse($definition->expr),
            $definition instanceof Op\Expr\Cast => $recurse($definition->expr),
            $definition instanceof Op\Expr\BinaryOp => $recurse($definition->left) && $recurse($definition->right),
            $definition instanceof Op\Expr\ConcatList => $this->all($definition->list, $recurse),
            $definition instanceof Op\Expr\Array_ => $this->all($definition->values, $recurse),
            $definition instanceof Op\Phi => $this->all($definition->vars, $recurse),
            $definition instanceof Op\Iterator\Value,
            $definition instanceof Op\Iterator\Key => $recurse($definition->var),
            $definition instanceof Op\Expr\ArrayDimFetch => $recurse($definition->var),
            $definition instanceof Op\Expr\PropertyFetch => $this->isSafeDatabaseIdentifier($definition),
            $definition instanceof Op\Expr\FuncCall,
            $definition instanceof Op\Expr\NsFuncCall => $this->checkFunctionCall(
                $definition->name,
                $definition->args,
                $recurse,
            ),
            $definition instanceof Op\Expr\MethodCall => $this->checkMethodCall($definition),
            default => false,
        };
    }

    /**
     * @param array<array-key, mixed> $operands
     * @param callable(Operand): bool $recurse
     */
    private function all(array $operands, callable $recurse): bool
    {
        foreach ($operands as $operand) {
            if (! $operand instanceof Operand || ! $recurse($operand)) {
                return false;
            }
        }

        return true;
    }

    /**
     * A call is effectively literal when the catalogue says its result cannot
     * carry SQL syntax, or when it merely passes through arguments that are all
     * themselves effectively literal.
     *
     * @param array<array-key, mixed> $args
     * @param callable(Operand): bool $recurse
     */
    private function checkFunctionCall(Operand $name, array $args, callable $recurse): bool
    {
        $function = OperandHelper::literalString($name);

        if ($function === null) {
            return false;
        }

        $matcher = Matcher::function($function);

        // absint(), intval(), count(), md5(), sanitize_key()… nothing that
        // comes out of these can be SQL syntax. esc_sql() is here too, and is
        // only true of it inside quotes — see TaintKind::SqlUnquoted, which is
        // what carries that distinction.
        if ($this->clearsSql($matcher)) {
            return true;
        }

        $propagator = $this->registry->propagator($matcher);

        if ($propagator === null) {
            return false;
        }

        foreach ($propagator->arguments->resolve(count($args)) as $index) {
            $argument = $args[$index] ?? null;

            if (! $argument instanceof Operand || ! $recurse($argument)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The output of an inner `$wpdb->prepare()` is already escaped SQL, so
     * concatenating it into an outer format string is safe.
     */
    private function checkMethodCall(Op\Expr\MethodCall $call): bool
    {
        $method = OperandHelper::literalString($call->name);

        if ($method === null || ! $this->clearsSql(Matcher::method('wpdb', $method))) {
            return false;
        }

        return $this->isDatabaseHandle($call->var);
    }

    private function clearsSql(Matcher $matcher): bool
    {
        $sanitizer = $this->registry->sanitizer($matcher);

        return $sanitizer !== null
            && ($sanitizer->clearsEverything || $sanitizer->clears->has(TaintKind::Sql));
    }

    /**
     * `$wpdb`, `$this->wpdb`, `$this->db`, `aioseo()->core->db->db`.
     */
    private function isDatabaseHandle(Operand $receiver): bool
    {
        $name = OperandHelper::variableName($receiver);

        if ($name !== null) {
            return in_array(strtolower($name), ['wpdb', 'db'], true);
        }

        $definition = OperandHelper::definingOp($receiver);

        if (! $definition instanceof Op\Expr\PropertyFetch) {
            return false;
        }

        $property = OperandHelper::literalString($definition->name);

        return $property !== null && in_array(strtolower($property), ['wpdb', 'db'], true);
    }

    /**
     * `{$wpdb->prefix}`, `{$wpdb->posts}` and the rest of the table-name
     * properties.
     */
    private function isSafeDatabaseIdentifier(Op\Expr\PropertyFetch $fetch): bool
    {
        $property = OperandHelper::literalString($fetch->name);

        if ($property === null || ! $this->isDatabaseHandle($fetch->var)) {
            return false;
        }

        // The catalogue's list is documentation of the core table properties.
        // Any other property of $wpdb counts too, provided nothing tainted was
        // ever written to it.
        return in_array($property, $this->registry->safeDatabaseIdentifiers(), true)
            || $this->properties->get('wpdb', $property)->isEmpty();
    }
}
