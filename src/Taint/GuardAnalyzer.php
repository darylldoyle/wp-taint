<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Operand;

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

    /**
     * Functions that normalise a value without adding to it, so that a check
     * of the normalised value and a later use of it are the same value.
     */
    private const NORMALISERS = ['strtoupper', 'strtolower', 'trim', 'ltrim', 'rtrim', 'sanitize_key'];

    /**
     * WordPress functions that end the request, so a branch calling one never
     * reaches the code after it.
     */
    private const NEVER_RETURN = [
        'wp_die', 'wp_send_json', 'wp_send_json_success', 'wp_send_json_error', 'wp_nonce_ays',
    ];

    /** Dominators, per function. */
    private ?BlockDominators $dominators = null;

    /** @var array<string, bool> isGuarded() answers for this function, by operand and block */
    private array $answers = [];

    /** The function's first block, the one block with no parents that runs. */
    private ?Block $entry = null;

    /**
     * Start a new function. Dominance is a property of one block graph.
     *
     * @param list<Block> $blocks
     */
    public function forFunction(array $blocks): void
    {
        $this->dominators = BlockDominators::compute($blocks);
        $this->entry = $blocks[0] ?? null;
        $this->answers = [];
    }

    public function isGuarded(Operand $operand, ?Block $block): bool
    {
        if ($block === null || $this->dominators === null || ! $this->dominators->covers($block)) {
            return false;
        }

        // Fixed for the function, and asked again on every pass of the fixed
        // point for every input to a concatenation.
        $key = spl_object_id($operand) . ':' . spl_object_id($block);

        return $this->answers[$key] ??= $this->answer($operand, $block);
    }

    private function answer(Operand $operand, Block $block): bool
    {
        if ($this->dominators === null) {
            return false;
        }

        $names = $this->namesOf($operand);

        if ($names === []) {
            return false;
        }

        $dominating = $this->dominators->of($block);

        // Every block that must have been passed through to get here. If one of
        // them can only be entered by the validating side of a guard on this
        // value, there was no way round it.
        //
        // Every way in has to validate or be a dead end, not just one.
        // `if ( ! ctype_digit( $x ) ) { $y = 1; }` jumps straight to the block
        // after it on the edge where the check passed, and falls into the same
        // block from the branch that never looked at $x. Crediting the one
        // edge left `echo $x` after it unreported. A branch that returns or
        // dies first still falls in as far as the CFG says, and never runs
        // that far.
        foreach ($dominating as $candidate) {
            if ($this->enteredOnlyValidated($candidate, $names)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether every edge into this block is the validating side of a guard,
     * or comes from a block that never gets as far as its jump, and at least
     * one validates.
     *
     * @param list<string> $names
     */
    private function enteredOnlyValidated(Block $block, array $names): bool
    {
        $validated = false;

        foreach ($block->parents as $parent) {
            $terminal = $parent->children[count($parent->children) - 1] ?? null;

            if ($terminal instanceof Op\Stmt\JumpIf && $this->validatesOnEdge($terminal, $block, $names)) {
                $validated = true;

                continue;
            }

            if (! $this->endsBeforeJumping($parent) && ! $this->replacesWithLiteral($parent, $names)) {
                return false;
            }
        }

        return $validated;
    }

    /**
     * Whether this branch, or the straight line of blocks leading only to it,
     * replaces the checked variable with a literal before falling through.
     *
     * The fallback form of an allowlist:
     *
     * ```php
     * if ( ! in_array( $mode, array( 'grid', 'list' ), true ) ) {
     *     $mode = 'grid';
     * }
     * ```
     *
     * The branch that failed the check does not carry the unchecked value on.
     * Only a literal counts. Anything else could be as tainted as what it
     * replaced, and a guarded sink is not reported at all.
     *
     * @param list<string> $names
     */
    private function replacesWithLiteral(Block $block, array $names): bool
    {
        for ($depth = 0; $depth < 8; $depth++) {
            foreach ($block->children as $op) {
                if (
                    $op instanceof Op\Expr\Assign
                    && array_intersect($this->namesOf($op->var), $names) !== []
                    && self::isLiteralValue($op->expr)
                ) {
                    return true;
                }
            }

            $parent = count($block->parents) === 1 ? reset($block->parents) : null;

            if (! $parent instanceof Block) {
                return false;
            }

            $terminal = $parent->children[count($parent->children) - 1] ?? null;

            // Up to the branch that decided, not past it.
            if ($terminal instanceof Op\Stmt\JumpIf) {
                return false;
            }

            $block = $parent;
        }

        return false;
    }

    private static function isLiteralValue(Operand $operand): bool
    {
        if ($operand instanceof Operand\Literal) {
            return true;
        }

        $definition = OperandHelper::definingOp($operand);

        return $definition instanceof Op\Expr\ConstFetch;
    }

    /**
     * Whether control never leaves this block by its last op: it, or the
     * straight line of blocks leading only to it, returns, throws, exits or
     * calls something that never returns, or nothing reaches it at all.
     *
     * php-cfg ends the block at a `return` and starts a fresh one for
     * whatever follows, which then falls through to the block after the
     * `if`. That edge never runs, which is why a guard clause works.
     */
    private function endsBeforeJumping(Block $block): bool
    {
        for ($depth = 0; $depth < 8; $depth++) {
            if (self::stops($block)) {
                return true;
            }

            $parent = count($block->parents) === 1 ? reset($block->parents) : null;

            if (! $parent instanceof Block) {
                return $block->parents === [] && $block !== $this->entry;
            }

            $block = $parent;
        }

        return false;
    }

    private static function stops(Block $block): bool
    {
        foreach ($block->children as $op) {
            if (
                $op instanceof Op\Terminal\Return_
                || $op instanceof Op\Terminal\Throw_
                || $op instanceof Op\Terminal\Exit_
            ) {
                return true;
            }

            // Inside a namespace an unqualified call is an NsFuncCall, whose
            // `name` is the global function it falls back to.
            if ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall) {
                $name = strtolower(ltrim(OperandHelper::literalString($op->name) ?? '', '\\'));

                if (in_array($name, self::NEVER_RETURN, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Whether this condition coming out true proves the value safe.
     *
     * The same test a branch is put to, for a condition that is not a branch:
     * `return in_array( $type, array( 'post', 'term' ), true );` in a REST
     * permission callback lets a request through only when it is true.
     */
    public function provesWhenTrue(Operand $condition, Operand $value): bool
    {
        $names = $this->namesOf($value);
        $positive = true;

        if ($names === []) {
            return false;
        }

        while (true) {
            $definition = OperandHelper::definingOp($condition);

            if ($definition instanceof Op\Expr\BooleanNot) {
                $positive = ! $positive;
                $condition = $definition->expr;

                continue;
            }

            if ($definition instanceof Op\Expr\Cast\Bool_) {
                $condition = $definition->expr;

                continue;
            }

            // True overall only tells us about the joined operand when true is
            // not the constant it was joined with. See validatesOnEdge().
            if ($definition instanceof Op\Phi) {
                $joined = self::shortCircuited($definition);

                if ($joined === null || $positive === $joined[0]) {
                    return false;
                }

                $condition = $joined[1];

                continue;
            }

            if (! $definition instanceof Op\Expr\FuncCall && ! $definition instanceof Op\Expr\NsFuncCall) {
                return false;
            }

            $safeWhen = $this->safeWhen($definition, $names);

            return $safeWhen !== null && $safeWhen === $positive;
        }
    }

    /**
     * The join php-cfg writes for `&&` and `||`: a constant from the path that
     * short-circuited, and the right-hand operand from the path that did not.
     *
     * `a && b` joins `false` with `b`, and `a || b` joins `true` with `b`.
     * Wherever the join is not that constant, it is `b`'s value, and `a` came
     * out the way that let `b` run. Wherever it is the constant, nothing is
     * known about `b`.
     *
     * @return array{0: bool, 1: Operand}|null the constant, and the joined operand
     */
    private static function shortCircuited(Op\Phi $phi): ?array
    {
        if (count($phi->vars) !== 2) {
            return null;
        }

        $vars = array_values($phi->vars);
        $first = $vars[0] ?? null;
        $second = $vars[1] ?? null;

        foreach ([[$first, $second], [$second, $first]] as [$constant, $operand]) {
            if (
                $constant instanceof Operand\Literal && is_bool($constant->value)
                && $operand instanceof Operand && ! $operand instanceof Operand\Literal
            ) {
                return [$constant->value, $operand];
            }
        }

        return null;
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

            if ($definition instanceof Op\Expr\Cast\Bool_) {
                $operand = $definition->expr;

                continue;
            }

            // `isset( $x ) && in_array( $x, … )` joins `false`, from the path
            // where isset() failed, with in_array()'s result. The join tells
            // us in_array() came out true only on the edge where it is not
            // that constant: see shortCircuited().
            if ($definition instanceof Op\Phi) {
                $joined = self::shortCircuited($definition);

                if ($joined === null) {
                    return false;
                }

                [$constant, $operand] = $joined;
                $informative = $positive === ! $constant ? $jump->if : $jump->else;

                if ($informative !== $arrivedAt) {
                    return false;
                }

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
    private function namesOf(Operand $operand, int $depth = 0): array
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

        if ($depth < 4) {
            $expression = $this->expressionName($operand, $depth);

            if ($expression !== null) {
                $names[] = $expression;
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * A name for an expression that means the same thing each time it is
     * written.
     *
     * An element under a literal key, `$params['orderby']`, is read afresh
     * into a new temporary each time, so it has no variable name to be tied
     * by. Named `params['orderby']` here, the guard and the use match:
     *
     * ```php
     * if ( in_array( $params['orderby'], array( 'ip', 'url' ), true ) ) {
     *     $query['orderby'] = $params['orderby'];
     * }
     * ```
     *
     * A normaliser around a named value, `strtoupper( $params['direction'] )`,
     * is named the same way, because checking the normalised value against a
     * list and then using it is the other common form. No variable name can
     * contain `[` or `(`, so these cannot collide with one.
     */
    private function expressionName(Operand $operand, int $depth): ?string
    {
        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\ArrayDimFetch && $definition->dim instanceof Operand) {
            $key = OperandHelper::literalKey($definition->dim);
            $base = $this->namesOf($definition->var, $depth + 1)[0] ?? null;

            return $key === null || $base === null ? null : $base . '[' . var_export($key, true) . ']';
        }

        if (
            ($definition instanceof Op\Expr\FuncCall || $definition instanceof Op\Expr\NsFuncCall)
            && count($definition->args) === 1
        ) {
            $function = strtolower(ltrim(OperandHelper::literalString($definition->name) ?? '', '\\'));
            $argument = $definition->args[0] ?? null;

            if (! in_array($function, self::NORMALISERS, true) || ! $argument instanceof Operand) {
                return null;
            }

            $base = $this->namesOf($argument, $depth + 1)[0] ?? null;

            return $base === null ? null : $function . '(' . $base . ')';
        }

        return null;
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
    private function isLiteralArray(Operand $operand, int $depth = 0): bool
    {
        $definition = OperandHelper::definingOp($operand);

        // `$allowed = array( … ); in_array( $x, $allowed, true )` is how an
        // allowlist is usually written, and only the inline literal counted.
        if ($definition instanceof Op\Expr\Assign && $depth < 8) {
            return $this->isLiteralArray($definition->expr, $depth + 1);
        }

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
