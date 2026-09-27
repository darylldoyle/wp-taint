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
    /**
     * Predicates that admit only a fixed set of characters, and which.
     *
     * What that proves depends on the kind: see {@see CharacterProof}. The
     * `ctype_*` family reads the C locale, which is ASCII.
     */
    private const CHARACTER_SETS = [
        'ctype_digit' => '0123456789',
        'ctype_alnum' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        'ctype_alpha' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'ctype_xdigit' => '0123456789abcdefABCDEF',
        'ctype_lower' => 'abcdefghijklmnopqrstuvwxyz',
        'ctype_upper' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    ];

    /**
     * Predicates that admit only a number or a boolean. `is_numeric()` also
     * admits leading and trailing whitespace, which the number's grammar
     * leaves harmless, so these are credited as the value they admit rather
     * than by the characters in it.
     */
    private const NUMERIC = ['is_numeric', 'is_int', 'is_integer', 'is_long', 'is_float', 'is_double', 'is_bool'];

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

    /** @var array<string, CharacterProof|null> proofFor() answers for this function, by operand and block */
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

    /**
     * Whether every way here checked the value against something that leaves
     * it no payload at all.
     */
    public function isGuarded(Operand $operand, ?Block $block): bool
    {
        return $this->proofFor($operand, $block)?->clearsEveryPayload() ?? false;
    }

    /**
     * What the checks on every way here prove about the value, or null when
     * there is a way round them.
     */
    public function proofFor(Operand $operand, ?Block $block): ?CharacterProof
    {
        if ($block === null || $this->dominators === null || ! $this->dominators->covers($block)) {
            return null;
        }

        // Fixed for the function, and asked again on every pass of the fixed
        // point for every input to a concatenation.
        $key = spl_object_id($operand) . ':' . spl_object_id($block);

        if (! array_key_exists($key, $this->answers)) {
            $this->answers[$key] = $this->answer($operand, $block);
        }

        return $this->answers[$key];
    }

    private function answer(Operand $operand, Block $block): ?CharacterProof
    {
        if ($this->dominators === null) {
            return null;
        }

        $names = $this->namesOf($operand);

        if ($names === []) {
            return null;
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
        //
        // Each guard passed on the way proves what it proves, and together they
        // prove all of it: a length check and then an allowlist.
        $proof = null;

        foreach ($dominating as $candidate) {
            $entered = $this->enteredOnlyValidated($candidate, $names);

            if ($entered !== null) {
                $proof = $proof === null ? $entered : $proof->and($entered);
            }
        }

        return $proof;
    }

    /**
     * Whether every edge into this block is the validating side of a guard,
     * or comes from a block that never gets as far as its jump, and at least
     * one validates.
     *
     * The value arrives by one of the edges, so only what every edge proves
     * holds. An edge that replaces the value with a literal proves everything.
     *
     * @param list<string> $names
     */
    private function enteredOnlyValidated(Block $block, array $names): ?CharacterProof
    {
        $proof = null;
        $validated = false;

        foreach ($block->parents as $parent) {
            $terminal = $parent->children[count($parent->children) - 1] ?? null;
            $edge = $terminal instanceof Op\Stmt\JumpIf ? $this->validatesOnEdge($terminal, $block, $names) : null;

            if ($edge === null && $this->endsBeforeJumping($parent)) {
                continue;
            }

            if ($edge === null && $this->replacesWithLiteral($parent, $names)) {
                $edge = CharacterProof::complete();
            } else {
                $validated = $validated || $edge !== null;
            }

            if ($edge === null) {
                return null;
            }

            $proof = $proof === null ? $edge : $proof->or($edge);
        }

        return $validated ? $proof : null;
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
        return $this->proofWhenTrue($condition, $value)?->clearsEveryPayload() ?? false;
    }

    private function proofWhenTrue(Operand $condition, Operand $value): ?CharacterProof
    {
        $names = $this->namesOf($value);
        $positive = true;

        if ($names === []) {
            return null;
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
                    return null;
                }

                $condition = $joined[1];

                continue;
            }

            if (! $definition instanceof Op\Expr\FuncCall && ! $definition instanceof Op\Expr\NsFuncCall) {
                return null;
            }

            $safe = $this->safeWhen($definition, $names);

            return $safe !== null && $safe[0] === $positive ? $safe[1] : null;
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
    private function validatesOnEdge(Op\Stmt\JumpIf $jump, Block $arrivedAt, array $names): ?CharacterProof
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
                    return null;
                }

                [$constant, $operand] = $joined;
                $informative = $positive === ! $constant ? $jump->if : $jump->else;

                if ($informative !== $arrivedAt) {
                    return null;
                }

                continue;
            }

            if (! $definition instanceof Op\Expr\FuncCall && ! $definition instanceof Op\Expr\NsFuncCall) {
                return null;
            }

            $safe = $this->safeWhen($definition, $names);

            if ($safe === null) {
                return null;
            }

            [$safeWhen, $proof] = $safe;

            // Which way the call has to come out for the value to be safe, and
            // then which edge that is once the negations are counted.
            //
            // These are not the same question, and treating them as one had the
            // polarity backwards for exactly the case that motivated the
            // denylist support: `ctype_digit()` proves safety when it
            // *succeeds*, `preg_match( '/[&<>]/' )` when it *fails*.
            $conditionIsTrue = $positive ? $safeWhen : ! $safeWhen;
            $wanted = $conditionIsTrue ? $jump->if : $jump->else;

            return $wanted === $arrivedAt ? $proof : null;
        }
    }

    /**
     * What this call has to evaluate to for the value to be safe, and what it
     * then proves.
     *
     * True for a predicate that confirms the value is acceptable, false for one
     * that detects something unacceptable, null when it says nothing at all.
     *
     * @param list<string> $names
     *
     * @return array{0: bool, 1: CharacterProof}|null
     */
    private function safeWhen(Op\Expr\FuncCall|Op\Expr\NsFuncCall $call, array $names): ?array
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

        $checksValue = fn (int $index): bool => isset($arguments[$index])
            && $this->refersTo($arguments[$index], $names);

        if (isset(self::CHARACTER_SETS[$function])) {
            return $checksValue(0) ? [true, CharacterProof::ofCharacters(self::CHARACTER_SETS[$function])] : null;
        }

        if (in_array($function, self::NUMERIC, true)) {
            return $checksValue(0) ? [true, CharacterProof::complete()] : null;
        }

        if ($function === 'in_array') {
            // Loose comparison is not a constraint: `in_array( '0abc', [ 0 ] )`
            // is true in PHP before 8, and the third-party suite marks the
            // loose form as a case an analyser should still flag.
            return isset($arguments[1], $arguments[2])
                && $checksValue(0)
                && $this->isTrue($arguments[2])
                && $this->isLiteralArray($arguments[1]) ? [true, CharacterProof::complete()] : null;
        }

        if ($function === 'array_key_exists') {
            return isset($arguments[1])
                && $checksValue(0)
                && $this->isLiteralArray($arguments[1]) ? [true, CharacterProof::complete()] : null;
        }

        if ($function === 'preg_match' && isset($arguments[0]) && $checksValue(1)) {
            // An anchored allowlist proves what it proves by matching; a bare
            // class proves the value lacks those characters by *not* matching.
            $matched = $this->patternProof($arguments[0], true);

            if ($matched !== null) {
                return [true, $matched];
            }

            $unmatched = $this->patternProof($arguments[0], false);

            return $unmatched === null ? null : [false, $unmatched];
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
     * What a `preg_match` proves about the value on the edge taken.
     *
     * Two shapes, and they are mirror images.
     *
     * **Matched, anchored class.** `/^[a-z0-9_-]+$/` succeeding proves the
     * value is those characters end to end. `/^\d/` proves nothing:
     * `1<script>` passes it, because the anchor covers only the first
     * character. A negated class, `/^[^<>]+$/`, proves the value is anything
     * but those characters. A `$` without `D` also matches before one final
     * newline, which carries nothing on its own.
     *
     * **Not matched, bare class.** `! preg_match( '/[&<>"\']/', $s )` proves the
     * value contains none of those characters. Core's `wp_specialchars()`
     * opens with exactly that as a fast path, and every plugin that vendors a
     * copy of it inherited a false positive from us, Duplicator's installer
     * among them.
     *
     * What either proves, kind by kind, is {@see CharacterProof}'s. A proof
     * that clears nothing is no proof.
     */
    private function patternProof(Operand $operand, bool $matched): ?CharacterProof
    {
        $literal = OperandHelper::literalString($operand);
        $pattern = $literal === null ? null : CharacterProof::pattern($literal);

        if ($pattern === null) {
            return null;
        }

        [$body, $caseless] = $pattern;
        $class = '((?:[^\]\\\\]|\\\\.)+)';
        $quantifier = '(?:[+*]|\{\d+(?:,\d*)?\})';

        if ($matched) {
            if (preg_match('/^\^\[(\^?)' . $class . '\]' . $quantifier . '\$$/', $body, $matches) !== 1) {
                return null;
            }

            $characters = CharacterProof::expandClass($matches[2], $caseless);

            if ($characters === null) {
                return null;
            }

            $proof = $matches[1] === '^'
                ? CharacterProof::ofAllExcept($characters)
                : CharacterProof::ofCharacters($characters);
        } else {
            if (
                preg_match('/^\[' . $class . '\]' . $quantifier . '?$/', $body, $matches) !== 1
                || str_starts_with($matches[1], '^')
            ) {
                return null;
            }

            $characters = CharacterProof::expandClass($matches[1], $caseless);

            if ($characters === null) {
                return null;
            }

            $proof = CharacterProof::ofAllExcept($characters);
        }

        return $proof->clears->isEmpty() ? null : $proof;
    }
}
