<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Did every path to here prove the value was one of a known-safe set?
 *
 * php-cfg writes an assertion into SSA for `is_int()` and its relatives, and
 * {@see AssertionNarrowing} reads it. It writes nothing for the checks people
 * actually use:
 *
 * ```php
 * if ( ! ctype_digit( $id ) ) {
 *     return;
 * }
 * update_option( 'acme_id', $id );          // digits only by now
 *
 * foreach ( $posted as $key => $value ) {
 *     if ( ! in_array( $key, $allowed, true ) ) {
 *         continue;
 *     }
 *     update_option( $key, $value );        // one of $allowed by now
 * }
 * ```
 *
 * Both were false positives. The second is WooCommerce's REST settings
 * controller, which survived three rounds of narrowing the option-name rule and
 * was the last thing standing; the first is a third-party fixture labelled
 * safe. A validating guard is how careful WordPress code is written, and not
 * seeing it made the tool wrong about careful code.
 *
 * ## Why this runs at reporting time
 *
 * Propagation is a fixed point over a single state per function, and every
 * convergence failure this project has had came from teaching that loop
 * something new. This asks a question instead: at the moment a sink is about to
 * be reported, walk back up the blocks and see whether we could only have
 * arrived here through a guard that validated this value.
 *
 * Nothing propagates, nothing iterates, so nothing can oscillate. The cost is
 * that it only suppresses a finding — it cannot make one appear — which is the
 * right direction for a check that is approximating.
 *
 * ## Dominance, not a walk up the parents
 *
 * The first attempt followed `Block::parents` and stopped at any join, on the
 * assumption that a guard clause leaves a linear chain. It does not: the
 * fall-through block of a guard has two predecessors in php-cfg's output, and
 * the check never fired once.
 *
 * So the question is asked properly. A value is guarded at a sink when the
 * block on the *validating* side of the branch **dominates** the sink — every
 * path from the function's entry to the sink passes through it. That is a
 * standard fixed point over the block graph, computed once per function, and it
 * gives a yes only when there is genuinely no way round the guard.
 */
final class GuardAnalyzer
{
    /** Dominance settles in a handful of rounds; this is a runaway backstop. */
    private const MAX_ROUNDS = 32;

    /** Characters that can carry syntax in any context this engine models. */
    private const DANGEROUS = '<>"\'`;()&|$\\/=%{} ';

    /**
     * Predicates that constrain a value to something harmless.
     *
     * `ctype_*` admit only characters from a fixed class, none of which can
     * open a quote, a tag or a statement. `in_array` and `array_key_exists`
     * constrain to a set the code chose. `preg_match` is handled separately,
     * because whether it constrains depends on the pattern.
     */
    private const CHARACTER_CLASSES = [
        'ctype_digit', 'ctype_alnum', 'ctype_alpha', 'ctype_xdigit', 'ctype_lower', 'ctype_upper',
        'is_numeric', 'is_int', 'is_integer', 'is_long', 'is_float', 'is_double', 'is_bool',
    ];

    /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>>|null dominators, per function */
    private ?SplObjectStorage $dominators = null;

    /**
     * Start a new function. Dominance is a property of one block graph.
     *
     * @param list<Block> $blocks
     */
    public function forFunction(array $blocks): void
    {
        $this->dominators = $blocks === [] ? null : self::computeDominators($blocks);
    }

    public function isGuarded(Operand $operand, ?Block $block): bool
    {
        if ($block === null || $this->dominators === null || ! $this->dominators->contains($block)) {
            return false;
        }

        $names = $this->namesOf($operand);

        if ($names === []) {
            return false;
        }

        /** @var SplObjectStorage<Block, true> $dominating */
        $dominating = $this->dominators[$block];

        // Every block that must have been passed through to get here. If one of
        // them is the validating side of a guard on this value, there was no
        // way round it.
        foreach ($dominating as $candidate) {
            foreach ($candidate->parents as $parent) {
                $terminal = $parent->children[count($parent->children) - 1] ?? null;

                if ($terminal instanceof Op\Stmt\JumpIf && $this->validatesOnEdge($terminal, $candidate, $names)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Which blocks every path to each block must pass through.
     *
     * The textbook iterative formulation: a block is dominated by itself and by
     * everything that dominates all of its predecessors. Started pessimistically
     * with every block dominating every block, and narrowed until it settles.
     *
     * @param list<Block> $blocks
     *
     * @return SplObjectStorage<Block, SplObjectStorage<Block, true>>
     */
    private static function computeDominators(array $blocks): SplObjectStorage
    {
        $entry = $blocks[0] ?? null;

        /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>> $empty */
        $empty = new SplObjectStorage();

        if ($entry === null) {
            return $empty;
        }

        /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>> $dominators */
        $dominators = new SplObjectStorage();

        foreach ($blocks as $block) {
            /** @var SplObjectStorage<Block, true> $all */
            $all = new SplObjectStorage();

            foreach ($blocks as $other) {
                $all->attach($other, true);
            }

            $dominators->attach($block, $all);
        }

        /** @var SplObjectStorage<Block, true> $entryOnly */
        $entryOnly = new SplObjectStorage();
        $entryOnly->attach($entry, true);
        $dominators[$entry] = $entryOnly;

        for ($round = 0; $round < self::MAX_ROUNDS; $round++) {
            $changed = false;

            foreach ($blocks as $block) {
                if ($block === $entry) {
                    continue;
                }

                $intersection = null;

                foreach ($block->parents as $parent) {
                    if (! $dominators->contains($parent)) {
                        continue;
                    }

                    /** @var SplObjectStorage<Block, true> $parentDominators */
                    $parentDominators = $dominators[$parent];

                    if ($intersection === null) {
                        /** @var SplObjectStorage<Block, true> $intersection */
                        $intersection = clone $parentDominators;

                        continue;
                    }

                    // SplObjectStorage's intersection is removeAllExcept().
                    $intersection->removeAllExcept($parentDominators);
                }

                /** @var SplObjectStorage<Block, true> $next */
                $next = $intersection ?? new SplObjectStorage();
                $next->attach($block, true);

                /** @var SplObjectStorage<Block, true> $current */
                $current = $dominators[$block];

                if (count($next) !== count($current)) {
                    $dominators[$block] = $next;
                    $changed = true;
                }
            }

            if (! $changed) {
                break;
            }
        }

        return $dominators;
    }

    /**
     * Does this branch prove the value safe on the edge we arrived by?
     *
     * `if ( ! ctype_digit( $id ) ) { return; }` validates on the *else* edge;
     * `if ( ctype_digit( $id ) ) { use( $id ); }` on the *if* edge. Every
     * `BooleanNot` between the call and the condition flips which.
     *
     * @param list<string> $names
     */
    private function validatesOnEdge(Op\Stmt\JumpIf $jump, Block $arrivedAt, array $names): bool
    {
        $positive = true;
        $operand = $jump->cond;

        while (true) {
            $definition = OperandHelper::definingOp($operand);

            if ($definition instanceof Op\Expr\BooleanNot) {
                $positive = ! $positive;
                $operand = $definition->expr;

                continue;
            }

            if (! $definition instanceof Op\Expr\FuncCall && ! $definition instanceof Op\Expr\NsFuncCall) {
                return false;
            }

            $safeWhen = $this->safeWhen($definition, $names);

            if ($safeWhen === null) {
                return false;
            }

            // Which way the call has to come out for the value to be safe, and
            // then which edge that is once the negations are counted.
            //
            // These are not the same question, and treating them as one had the
            // polarity backwards for exactly the case that motivated the
            // denylist support: `ctype_digit()` proves safety when it
            // *succeeds*, `preg_match( '/[&<>]/' )` when it *fails*.
            $conditionIsTrue = $positive ? $safeWhen : ! $safeWhen;
            $wanted = $conditionIsTrue ? $jump->if : $jump->else;

            return $wanted === $arrivedAt;
        }
    }

    /**
     * What this call has to evaluate to for the value to be safe.
     *
     * True for a predicate that confirms the value is acceptable, false for one
     * that detects something unacceptable, null when it says nothing at all.
     *
     * @param list<string> $names
     */
    private function safeWhen(Op\Expr\FuncCall|Op\Expr\NsFuncCall $call, array $names): ?bool
    {
        $function = OperandHelper::literalString($call->name);

        if ($function === null) {
            return null;
        }

        $function = strtolower(ltrim($function, '\\'));
        $arguments = array_values(array_filter(
            $call->args,
            static fn (mixed $argument): bool => $argument instanceof Operand,
        ));

        if (in_array($function, self::CHARACTER_CLASSES, true)) {
            return isset($arguments[0]) && $this->refersTo($arguments[0], $names) ? true : null;
        }

        if ($function === 'in_array') {
            // Loose comparison is not a constraint: `in_array( '0abc', [ 0 ] )`
            // is true in PHP before 8, and the third-party suite marks the
            // loose form as a case an analyser should still flag.
            return isset($arguments[0], $arguments[1], $arguments[2])
                && $this->refersTo($arguments[0], $names)
                && $this->isTrue($arguments[2])
                && $this->isLiteralArray($arguments[1]) ? true : null;
        }

        if ($function === 'array_key_exists') {
            return isset($arguments[0], $arguments[1])
                && $this->refersTo($arguments[0], $names)
                && $this->isLiteralArray($arguments[1]) ? true : null;
        }

        if (
            $function === 'preg_match' && isset($arguments[0], $arguments[1])
            && $this->refersTo($arguments[1], $names)
        ) {
            // An anchored allowlist proves safety by matching; a bare class of
            // dangerous characters proves it by *not* matching.
            if ($this->patternConstrains($arguments[0], true)) {
                return true;
            }

            return $this->patternConstrains($arguments[0], false) ? false : null;
        }

        return null;
    }

    /**
     * The variable names an operand stands for.
     *
     * SSA renames on every write, so the operand at the sink is rarely the one
     * the guard tested. The original name is what ties them together, which is
     * approximate in exactly one direction: a *different* variable of the same
     * name would be credited. Since this only ever suppresses, and a guard on
     * `$id` followed by a sink on a different `$id` is not something real code
     * does, that is the safe side to be wrong on.
     *
     * @return list<string>
     */
    private function namesOf(Operand $operand): array
    {
        $names = [];

        foreach ([$operand, $operand instanceof Operand\Temporary ? $operand->original : null] as $candidate) {
            if (! $candidate instanceof Operand\Variable) {
                continue;
            }

            $name = $candidate->name;

            if ($name instanceof Operand\Literal && is_string($name->value)) {
                $names[] = $name->value;
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * @param list<string> $names
     */
    private function refersTo(Operand $operand, array $names): bool
    {
        foreach ($this->namesOf($operand) as $name) {
            if (in_array($name, $names, true)) {
                return true;
            }
        }

        return false;
    }

    private function isTrue(Operand $operand): bool
    {
        if ($operand instanceof Operand\Literal) {
            return $operand->value === true;
        }

        $definition = OperandHelper::definingOp($operand);

        if (! $definition instanceof Op\Expr\ConstFetch) {
            return false;
        }

        $name = OperandHelper::literalString($definition->name);

        return $name !== null && strtolower($name) === 'true';
    }

    /**
     * An array whose every element is a literal, so the set is knowable.
     */
    private function isLiteralArray(Operand $operand): bool
    {
        $definition = OperandHelper::definingOp($operand);

        if (! $definition instanceof Op\Expr\Array_ || $definition->values === []) {
            return false;
        }

        foreach ($definition->values as $value) {
            if (! $value instanceof Operand\Literal) {
                return false;
            }
        }

        return true;
    }

    /**
     * Does this `preg_match` prove the value harmless on the edge taken?
     *
     * Two shapes, and they are mirror images.
     *
     * **Matched, anchored allowlist.** `/^[a-z0-9_-]+$/` succeeding proves the
     * value is those characters end to end. `/^\d/` proves nothing —
     * `1<script>` passes it, because the anchor covers only the first
     * character.
     *
     * **Not matched, denylist.** `! preg_match( '/[&<>"\']/', $s )` proves the
     * value contains none of those characters, which is the same conclusion
     * reached from the other direction. Core's `wp_specialchars()` opens with
     * exactly that as a fast path, and every plugin that vendors a copy of it
     * inherited a false positive from us — Duplicator's installer among them.
     *
     * Anything else is left unconstrained. This suppresses findings, and a
     * wrong yes hides a real one.
     */
    private function patternConstrains(Operand $operand, bool $matched): bool
    {
        $pattern = OperandHelper::literalString($operand);

        if ($pattern === null || strlen($pattern) < 3) {
            return false;
        }

        $delimiter = $pattern[0];
        $end = strrpos($pattern, $delimiter);

        if ($end === false || $end === 0) {
            return false;
        }

        $body = substr($pattern, 1, $end - 1);

        if ($matched) {
            return preg_match('/^\^\[([^\]]+)\]([+*])\$$/', $body, $matches) === 1
                && $this->classIsHarmless($matches[1]);
        }

        // Failing to match a bare class of dangerous characters proves none of
        // them is present.
        return preg_match('/^\[([^\]]+)\][+*]?$/', $body, $matches) === 1
            && ! str_starts_with($matches[1], '^')
            && $this->classIsOnlyDangerous($matches[1]);
    }

    /**
     * A class made up entirely of characters that carry syntax.
     *
     * Requiring *only* dangerous characters is what keeps this honest: a
     * denylist that also mentions harmless ones proves less than it appears to,
     * and `[a]` failing to match says nothing worth acting on.
     */
    private function classIsOnlyDangerous(string $class): bool
    {
        $expanded = self::expand($class);

        if ($expanded === null || $expanded === '') {
            return false;
        }

        $length = strlen($expanded);

        for ($index = 0; $index < $length; $index++) {
            if (strpos(self::DANGEROUS, $expanded[$index]) === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Every character a class admits, with ranges expanded.
     *
     * A negated class admits everything not listed, which is never a
     * constraint worth crediting.
     */
    private function classIsHarmless(string $class): bool
    {
        if (str_starts_with($class, '^')) {
            return false;
        }

        $expanded = self::expand($class);

        return $expanded !== null && strpbrk($expanded, self::DANGEROUS) === false;
    }

    /**
     * A character class with its ranges written out.
     */
    private static function expand(string $class): ?string
    {
        return preg_replace_callback(
            '/(\w)-(\w)/',
            static fn (array $m): string => implode('', range($m[1], $m[2])),
            $class,
        );
    }
}
