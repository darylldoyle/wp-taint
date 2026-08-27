<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Answers "did the engine actually understand where this value came from?"
 *
 * This is what separates the shape rule from a noise machine. Both of these
 * interpolate a variable into a query:
 *
 *     $id = absint( $_GET['id'] );
 *     $wpdb->query( "DELETE FROM t WHERE id = {$id}" );          // safe
 *
 *     $order = some_helper_we_cannot_see();
 *     $wpdb->get_results( "SELECT * FROM t ORDER BY {$order}" ); // unknown
 *
 * Taint analysis correctly reports neither, because neither carries sql taint.
 * A pure shape rule reports both, and the first is a false positive on the most
 * common safe idiom there is. The difference is that the first value's origin
 * is fully accounted for — a registry sanitizer applied to a known source — and
 * the second's is not.
 *
 * So `wp.sqli.unprepared-query` fires only where this returns false.
 */
final class OriginClassifier
{
    private const MAX_DEPTH = 24;

    public function __construct(
        private readonly Registry $registry,
        private readonly CallResolver $resolver,
    ) {
    }

    public function isFullyResolved(Operand $operand, FunctionContext $context, ClassTypeMap $types): bool
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();

        return $this->check($operand, $context, $types, $seen, 0);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function check(
        Operand $operand,
        FunctionContext $context,
        ClassTypeMap $types,
        SplObjectStorage $seen,
        int $depth,
    ): bool {
        if ($depth > self::MAX_DEPTH) {
            return false;
        }

        // A cycle means a loop-carried value, which we have already accounted
        // for by the time we come back round to it.
        if ($seen->contains($operand)) {
            return true;
        }

        $seen->attach($operand);

        if ($operand instanceof Operand\Literal) {
            return true;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            // No writer: a superglobal, a parameter, or a variable defined
            // somewhere we cannot see. Superglobals are modelled; the rest are
            // not.
            $name = OperandHelper::variableName($operand);

            return $name !== null && $this->registry->source(Matcher::superglobal($name)) !== null;
        }

        return $this->checkOp($definition, $context, $types, $seen, $depth);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function checkOp(
        Op $definition,
        FunctionContext $context,
        ClassTypeMap $types,
        SplObjectStorage $seen,
        int $depth,
    ): bool {
        $recurse = fn (Operand $next): bool => $this->check($next, $context, $types, $seen, $depth + 1);

        return match (true) {
            $definition instanceof Op\Expr\ConstFetch,
            $definition instanceof Op\Expr\ClassConstFetch,
            $definition instanceof Op\Expr\New_ => true,
            $definition instanceof Op\Expr\Assign,
            $definition instanceof Op\Expr\AssignRef => $recurse($definition->expr),
            $definition instanceof Op\Expr\Cast => $recurse($definition->expr),
            $definition instanceof Op\Expr\ArrayDimFetch => $recurse($definition->var),
            $definition instanceof Op\Expr\BinaryOp => $recurse($definition->left) && $recurse($definition->right),
            $definition instanceof Op\Expr\ConcatList => $this->all($definition->list, $recurse),
            $definition instanceof Op\Expr\Array_ => $this->all($definition->values, $recurse),
            $definition instanceof Op\Phi => $this->all($definition->vars, $recurse),
            $definition instanceof Op\Expr\PropertyFetch => $this->isSafeDatabaseIdentifier($definition),
            $definition instanceof Op\Expr\FuncCall,
            $definition instanceof Op\Expr\NsFuncCall,
            $definition instanceof Op\Expr\MethodCall,
            $definition instanceof Op\Expr\StaticCall => $this->checkCall($definition, $context, $types, $recurse),
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
     * @param callable(Operand): bool $recurse
     */
    private function checkCall(
        Op\Expr $definition,
        FunctionContext $context,
        ClassTypeMap $types,
        callable $recurse,
    ): bool {
        $target = $this->resolver->resolve($definition, $context, $types);

        if ($target === null || ! $target->isResolved()) {
            return false;
        }

        $matcher = $target->matcher;

        if ($matcher !== null) {
            // A sanitizer's output is defined by the catalogue, whatever went
            // in. Same for an explicitly safe call.
            if ($this->registry->sanitizer($matcher) !== null || $this->registry->isSafeCall($matcher)) {
                return true;
            }

            // A source is modelled: if the value were dangerous it would be
            // carrying taint, and we would not be asking this question.
            if ($this->registry->source($matcher) !== null) {
                return true;
            }

            $propagator = $this->registry->propagator($matcher);

            if ($propagator !== null) {
                foreach ($propagator->arguments->resolve($target->argumentCount()) as $index) {
                    $argument = $target->argument($index);

                    if ($argument !== null && ! $recurse($argument)) {
                        return false;
                    }
                }

                return true;
            }
        }

        // A function in the scanned code: we analysed its body and produced a
        // summary for it, so its return value is accounted for.
        return $target->userFunctionKey !== null;
    }

    private function isSafeDatabaseIdentifier(Op\Expr\PropertyFetch $fetch): bool
    {
        $property = OperandHelper::literalString($fetch->name);

        return $property !== null && in_array($property, $this->registry->safeDatabaseIdentifiers(), true);
    }
}
