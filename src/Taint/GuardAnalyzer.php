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

    /**
     * @param ValueResolver|null $values folds a constant to the strings it can
     *     hold, so a loose comparison with one can be credited
     */
    public function __construct(private readonly ?ValueResolver $values = null)
    {
    }

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

        if ($this->namesOf($operand) === []) {
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
            $entered = $this->enteredOnlyValidated($candidate, $operand);

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
     */
    private function enteredOnlyValidated(Block $block, Operand $subject): ?CharacterProof
    {
        $proof = null;
        $validated = false;

        foreach ($block->parents as $parent) {
            $terminal = $parent->children[count($parent->children) - 1] ?? null;
            $edge = match (true) {
                $terminal instanceof Op\Stmt\JumpIf => $this->validatesOnEdge($terminal, $block, $subject),
                $terminal instanceof Op\Stmt\Switch_ => $this->validatesOnCase($terminal, $block, $subject),
                default => null,
            };

            if ($edge === null && $this->endsBeforeJumping($parent)) {
                continue;
            }

            if ($edge === null && $this->replacesWithLiteral($parent, $subject)) {
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
     */
    private function replacesWithLiteral(Block $block, Operand $subject): bool
    {
        $names = $this->namesOf($subject);

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

        return $definition instanceof Op\Expr\ConstFetch || $definition instanceof Op\Expr\ClassConstFetch;
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
        return $this->namesOf($value) === [] ? null : $this->proofWhen($condition, true, $value);
    }

    /**
     * What a condition coming out this way proves about the value.
     *
     * Which way a check has to come out for the value to be safe, and which way
     * the condition came out once the negations are counted, are not the same
     * question. Treating them as one had the polarity backwards for exactly the
     * case that motivated the denylist support: `ctype_digit()` proves safety
     * when it *succeeds*, `preg_match( '/[&<>]/' )` when it *fails*.
     */
    private function proofWhen(Operand $condition, bool $outcome, Operand $subject, int $depth = 0): ?CharacterProof
    {
        if ($depth > 8) {
            return null;
        }

        $definition = OperandHelper::definingOp($condition);

        if ($definition instanceof Op\Expr\BooleanNot) {
            return $this->proofWhen($definition->expr, ! $outcome, $subject, $depth + 1);
        }

        if ($definition instanceof Op\Expr\Cast\Bool_) {
            return $this->proofWhen($definition->expr, $outcome, $subject, $depth + 1);
        }

        if ($definition instanceof Op\Phi) {
            return $this->joinedProof($definition, $outcome, $subject, $depth + 1);
        }

        // `empty( $x )` holds for a value that is one of '', '0', 0, null,
        // false or an empty array, and nothing else.
        $safe = match (true) {
            $definition instanceof Op\Expr\Empty_ => $this->refersTo($definition->expr, $subject)
                ? [true, CharacterProof::complete()]
                : null,
            $definition instanceof Op\Expr\BinaryOp => $this->comparisonProof($definition, $subject),
            $definition instanceof Op\Expr\FuncCall,
            $definition instanceof Op\Expr\NsFuncCall => $this->safeWhen($definition, $subject),
            default => null,
        };

        return $safe !== null && $safe[0] === $outcome ? $safe[1] : null;
    }

    /**
     * What `a && b` or `a || b` coming out this way proves.
     *
     * php-cfg joins the constant from the path that short-circuited, `false`
     * for `&&` and `true` for `||`, with `b` from the path that did not: see
     * shortCircuited(). Coming out the other way than that constant, both ran
     * and came out that way, so what either proves holds. Coming out as the
     * constant, either `a` did, or `a` came out the other way and `b` as the
     * constant. Only what both of those prove holds:
     *
     * ```php
     * if ( 'grid' === $mode || 'list' === $mode ) { … }
     * if ( 'grid' !== $mode && 'list' !== $mode ) { return; }
     * ```
     */
    private function joinedProof(Op\Phi $phi, bool $outcome, Operand $subject, int $depth): ?CharacterProof
    {
        $joined = self::shortCircuited($phi);

        if ($joined === null) {
            return null;
        }

        [$constant, $right] = $joined;
        $left = self::shortCircuitedLeft($phi, $constant);
        $ranOn = self::either(
            $left === null ? null : $this->proofWhen($left, ! $constant, $subject, $depth),
            $this->proofWhen($right, $outcome, $subject, $depth),
        );

        if ($outcome !== $constant) {
            return $ranOn;
        }

        $shortCircuit = $left === null ? null : $this->proofWhen($left, $constant, $subject, $depth);

        return $shortCircuit === null || $ranOn === null ? null : $shortCircuit->or($ranOn);
    }

    /**
     * What two facts that both hold prove, when either may prove nothing.
     */
    private static function either(?CharacterProof $first, ?CharacterProof $second): ?CharacterProof
    {
        if ($first === null || $second === null) {
            return $first ?? $second;
        }

        return $first->and($second);
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
     * The left-hand operand of the `&&` or `||` a join was written for: the
     * condition of the jump that went straight to the join with the constant.
     */
    private static function shortCircuitedLeft(Op\Phi $phi, bool $constant): ?Operand
    {
        $block = $phi->getAttribute('block');

        if (! $block instanceof Block) {
            return null;
        }

        foreach ($block->parents as $parent) {
            $terminal = $parent->children[count($parent->children) - 1] ?? null;

            if (
                $terminal instanceof Op\Stmt\JumpIf
                && $terminal->if !== $terminal->else
                && ($constant ? $terminal->if : $terminal->else) === $block
            ) {
                return $terminal->cond;
            }
        }

        return null;
    }

    /**
     * Does this branch prove the value safe on the edge we arrived by?
     *
     * `if ( ! ctype_digit( $id ) ) { return; }` validates on the *else* edge;
     * `if ( ctype_digit( $id ) ) { use( $id ); }` on the *if* edge.
     */
    private function validatesOnEdge(Op\Stmt\JumpIf $jump, Block $arrivedAt, Operand $subject): ?CharacterProof
    {
        if ($jump->if === $jump->else) {
            return null;
        }

        return match ($arrivedAt) {
            $jump->if => $this->proofWhen($jump->cond, true, $subject),
            $jump->else => $this->proofWhen($jump->cond, false, $subject),
            default => null,
        };
    }

    /**
     * Does a `switch` on the value enter this block only by its cases?
     *
     * `case 'grid':` compares loosely, so only a case that a loose comparison
     * cannot stretch counts: a string that is not numeric. `'1.0' == 1` and
     * `' 1' == '1'` both hold. A block the default also enters proves nothing.
     *
     */
    private function validatesOnCase(Op\Stmt\Switch_ $switch, Block $arrivedAt, Operand $subject): ?CharacterProof
    {
        if (! $this->refersTo($switch->cond, $subject) || $switch->default === $arrivedAt) {
            return null;
        }

        $cases = 0;

        foreach ($switch->targets as $index => $target) {
            if ($target !== $arrivedAt) {
                continue;
            }

            $case = $switch->cases[$index] ?? null;

            if (! $case instanceof Operand || ! $this->isLooseSafeLiteral($case)) {
                return null;
            }

            $cases++;
        }

        return $cases > 0 ? CharacterProof::complete() : null;
    }

    /**
     * What a comparison has to evaluate to for the value to be safe.
     *
     * `$x === 'grid'` settles the value when it holds, `$x !== 'grid'` when it
     * fails, against any literal or constant. A loose `==` or `!=` counts only
     * against a string that is not numeric, which it cannot stretch.
     *
     * @return array{0: bool, 1: CharacterProof}|null
     */
    private function comparisonProof(Op\Expr\BinaryOp $comparison, Operand $subject): ?array
    {
        $strict = $comparison instanceof Op\Expr\BinaryOp\Identical
            || $comparison instanceof Op\Expr\BinaryOp\NotIdentical;
        $loose = $comparison instanceof Op\Expr\BinaryOp\Equal
            || $comparison instanceof Op\Expr\BinaryOp\NotEqual;

        if (! $strict && ! $loose) {
            return null;
        }

        $other = match (true) {
            $this->refersTo($comparison->left, $subject) => $comparison->right,
            $this->refersTo($comparison->right, $subject) => $comparison->left,
            default => null,
        };

        if ($other === null) {
            return null;
        }

        $settles = $strict ? self::isLiteralValue($other) : $this->isLooseSafeLiteral($other);

        if (! $settles) {
            return null;
        }

        $whenTrue = $comparison instanceof Op\Expr\BinaryOp\Identical
            || $comparison instanceof Op\Expr\BinaryOp\Equal;

        return [$whenTrue, CharacterProof::complete()];
    }

    /**
     * A value a loose comparison cannot stretch: a string that is not numeric.
     *
     * A constant counts when it holds exactly one such string. Duplicator
     * dismisses a notice by name with `case AdminNotices::OPTION_KEY_…:`, and a
     * constant of unknown value could be `true`, which every non-empty string
     * loosely equals.
     */
    private function isLooseSafeLiteral(Operand $operand): bool
    {
        $value = OperandHelper::literalValue($operand);

        if (! $operand instanceof Operand\Literal) {
            $strings = $this->constantStrings($operand);
            $value = count($strings) === 1 ? $strings[0] : null;
        }

        return is_string($value) && $value !== '' && ! is_numeric(trim($value));
    }

    /**
     * @return list<string>
     */
    private function constantStrings(Operand $operand): array
    {
        $definition = OperandHelper::definingOp($operand);

        if (
            $this->values === null
            || (! $definition instanceof Op\Expr\ConstFetch && ! $definition instanceof Op\Expr\ClassConstFetch)
        ) {
            return [];
        }

        return $this->values->strings($operand);
    }

    /**
     * What this call has to evaluate to for the value to be safe, and what it
     * then proves.
     *
     * True for a predicate that confirms the value is acceptable, false for one
     * that detects something unacceptable, null when it says nothing at all.
     *
     * @return array{0: bool, 1: CharacterProof}|null
     */
    private function safeWhen(Op\Expr\FuncCall|Op\Expr\NsFuncCall $call, Operand $subject): ?array
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
            && $this->refersTo($arguments[$index], $subject);

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
            if (! isset($arguments[1], $arguments[2]) || ! $checksValue(0) || ! $this->isTrue($arguments[2])) {
                return null;
            }

            // A list the code built itself, from its own definitions, settles
            // the value as a literal one does, while it stays clean: WooCommerce
            // checks each setting a REST request names against
            // `array_keys( $settings_by_id )` before saving it.
            return $this->isLiteralArray($arguments[1])
                ? [true, CharacterProof::complete()]
                : [true, CharacterProof::complete()->requiringClean($arguments[1])];
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
     * The first test of whether a guard is about a value: a check on `$id`
     * says nothing about `$name`. A name is not enough on its own, because a
     * write after the check keeps the name and changes the value, so
     * refersTo() asks for the value too.
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

        $normalised = $definition === null ? null : self::normaliserOf($definition);

        if ($normalised === null) {
            return null;
        }

        $base = $this->namesOf($normalised[1], $depth + 1)[0] ?? null;

        return $base === null ? null : $normalised[0] . '(' . $base . ')';
    }

    /**
     * The normaliser a call applies, and the value it applies it to.
     *
     * @return array{0: string, 1: Operand}|null
     */
    private static function normaliserOf(Op $op): ?array
    {
        if ((! $op instanceof Op\Expr\FuncCall && ! $op instanceof Op\Expr\NsFuncCall) || count($op->args) !== 1) {
            return null;
        }

        $function = strtolower(ltrim(OperandHelper::literalString($op->name) ?? '', '\\'));
        $argument = $op->args[0] ?? null;

        return in_array($function, self::NORMALISERS, true) && $argument instanceof Operand
            ? [$function, $argument]
            : null;
    }

    /**
     * Whether the operand a guard tested is the value it is asked about.
     *
     * The same name is not enough. A value written after the check is not the
     * one it checked:
     *
     * ```php
     * if ( empty( $title ) ) {
     *     $title = $_POST['fallback'];
     *     echo $title;
     * }
     * ```
     *
     * So the value has to be the one tested, or a join of it with literals: the
     * fallback form of an allowlist writes one on the branch that failed. A
     * value computed from the tested one takes the proof where it is computed,
     * so it needs none here.
     */
    private function refersTo(Operand $tested, Operand $subject): bool
    {
        if (array_intersect($this->namesOf($tested), $this->namesOf($subject)) === []) {
            return false;
        }

        $seen = [];

        return $this->carriesOnly($subject, $tested, 0, $seen);
    }

    /**
     * Whether every value this operand can hold is the tested one or a literal.
     *
     * @param array<int, true> $seen joins already followed, so a loop ends
     */
    private function carriesOnly(Operand $value, Operand $tested, int $depth, array &$seen): bool
    {
        if ($this->sameValue($value, $tested, 0) || self::isLiteralValue($value)) {
            return true;
        }

        $definition = OperandHelper::definingOp($value);

        if ($definition instanceof Op\Expr\Assign && self::isLiteralValue($definition->expr)) {
            return true;
        }

        // php-cfg writes a narrowed copy of the value into each branch of an
        // `is_numeric()` check. The copy holds the same value.
        if ($definition instanceof Op\Expr\Assertion && $depth < 8) {
            return $this->carriesOnly($definition->expr, $tested, $depth + 1, $seen);
        }

        if (! $definition instanceof Op\Phi || $depth >= 8) {
            return false;
        }

        if (isset($seen[spl_object_id($definition)])) {
            return true;
        }

        $seen[spl_object_id($definition)] = true;

        foreach ($definition->vars as $var) {
            if (! $var instanceof Operand || ! $this->carriesOnly($var, $tested, $depth + 1, $seen)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether two operands hold the same value.
     *
     * SSA gives one operand per write, so a variable read twice is the same
     * operand. An element under a literal key and a normaliser around a value
     * are read afresh each time: see expressionName(). They are the same value
     * when they are the same read of the same value.
     */
    private function sameValue(Operand $first, Operand $second, int $depth): bool
    {
        if ($first === $second) {
            return true;
        }

        $one = OperandHelper::definingOp($first);
        $other = OperandHelper::definingOp($second);

        if ($one === null || $other === null || $depth >= 4) {
            return false;
        }

        // `( $x = $_GET['x'] ) === 'a'` tests the assignment's result, and a
        // later read of $x is the variable it wrote.
        if ($one === $other && $one instanceof Op\Expr\Assign) {
            return true;
        }

        if ($one instanceof Op\Expr\ArrayDimFetch && $other instanceof Op\Expr\ArrayDimFetch) {
            $key = $one->dim instanceof Operand ? OperandHelper::literalKey($one->dim) : null;
            $otherKey = $other->dim instanceof Operand ? OperandHelper::literalKey($other->dim) : null;

            return $key !== null && $key === $otherKey && $this->sameValue($one->var, $other->var, $depth + 1);
        }

        $normalised = self::normaliserOf($one);
        $otherNormalised = self::normaliserOf($other);

        return $normalised !== null
            && $otherNormalised !== null
            && $normalised[0] === $otherNormalised[0]
            && $this->sameValue($normalised[1], $otherNormalised[1], $depth + 1);
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
