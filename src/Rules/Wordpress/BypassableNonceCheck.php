<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Taint\GuardAnalyzer;
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;
use SplObjectStorage;

/**
 * A nonce check that an attacker skips by omitting the nonce.
 *
 * ```php
 * if ( isset( $_REQUEST['nonce'] ) && ! wp_verify_nonce( $_REQUEST['nonce'], 'x' )
 *     || ! current_user_can( 'manage_options' ) ) {
 * ```
 *
 * Send no `nonce` parameter at all and `isset()` is false, so the conjunction is
 * false, so `wp_die()` never runs. The guard reads as "check the nonce if one
 * was supplied", which is the same as not checking it: an attacker chooses what
 * to supply.
 *
 * ## The negation is the whole rule
 *
 * Without it the same shape is the correct idiom and fails closed:
 *
 * ```php
 * if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'x' ) ) {
 *     save();
 * }
 * ```
 *
 * Omit the nonce and nothing is saved. Matching on presence rather than parity
 * reported that in seven plugins and none of the real shape, which is telling
 * people a working CSRF check does not work.
 *
 * ## The precedence bug underneath
 *
 * `&&` binds tighter than `||`, so the expression above groups as
 * `(isset && !verify) || !can`, not as the author's evident intent. That makes
 * the capability check the only surviving guard, and issue 10 in the same
 * plugin — no exit after the redirect — means failing it does not stop anything
 * either.
 *
 * ## Scope
 *
 * Only the isset-guards-its-own-nonce shape, which is unambiguous. Deciding in
 * general whether a boolean expression can be short-circuited past is a much
 * larger question, and a rule that guesses at it would cost more in false
 * positives than it returns.
 *
 * ## When the missing nonce is handled anyway
 *
 * The conjunction being false for a missing nonce is only a bypass if nothing
 * else stops that request. Two places can, and the rule asks both before it
 * reports:
 *
 * ```php
 * // The condition around it: a missing nonce makes the whole test true.
 * if ( ! isset( $_POST['n'] ) || ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'x' ) ) ) {
 *     return false;
 * }
 *
 * // An earlier branch that ends the function when the nonce is missing.
 * if ( ! isset( $_POST['n'] ) ) {
 *     return;
 * }
 * if ( isset( $_POST['n'] ) && ! wp_verify_nonce( $_POST['n'], 'x' ) ) {
 *     wp_die();
 * }
 * ```
 *
 * Both are answered for the one case that matters, the nonce being absent,
 * with `isset()` of it false, `empty()` of it true, and everything else
 * unknown. The first stays quiet only when the whole condition is then
 * *certainly* the value a failed nonce gives it, so a missing nonce takes the
 * same branch as a wrong one. `… || ! current_user_can()` is unknown, and still
 * reported. The second stays quiet only when the earlier branch is certainly
 * taken and ends in `return`, `exit`, `throw` or a WordPress function that
 * never returns. `break` and `continue` do not count. They leave a loop, and
 * the work after the loop still runs. A `throw` inside a `try` does not count
 * either, since the `catch` can take it.
 */
final class BypassableNonceCheck implements StructuralRule
{
    private const RULE = 'wp.csrf.bypassable-nonce-check';

    private const VERIFIERS = ['wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer'];

    public function id(): string
    {
        return self::RULE;
    }

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array
    {
        $findings = [];
        $printer = new Standard();
        $parents = null;

        foreach (AstHelper::findAll($file->ast(), Node\Expr\BinaryOp\BooleanAnd::class) as $node) {
            if (! $node instanceof Node\Expr\BinaryOp\BooleanAnd) {
                continue;
            }

            $guarded = $this->issetOperand($node->left, $printer);

            if ($guarded === null) {
                continue;
            }

            if (! $this->deniesOnFailure($node->right, $guarded, $printer, false)) {
                continue;
            }

            // Built only for a file with a candidate, which is almost none of them.
            $parents ??= self::parents($file->ast());

            if ($this->handlesAbsence($node, $guarded, $parents, $file->ast(), $printer)) {
                continue;
            }

            $findings[] = StructuralFinding::at(
                $node,
                $file,
                $registry,
                self::RULE,
                Severity::High,
                sprintf(
                    'The nonce check only runs when %s is present, and the request decides whether to send it. '
                        . 'Omit the parameter and isset() is false, so the whole conjunction is false and nothing '
                        . 'is verified.',
                    $guarded,
                ),
                $guarded,
            );
        }

        return $findings;
    }

    /**
     * The single value an isset() on the left of the && is testing.
     *
     * Multi-argument isset() is not this shape and is left alone.
     */
    private function issetOperand(Node\Expr $left, Standard $printer): ?string
    {
        $vars = array_values($left instanceof Node\Expr\Isset_ ? $left->vars : []);

        if (count($vars) !== 1) {
            return null;
        }

        return $printer->prettyPrintExpr($vars[0]);
    }

    /**
     * Does the right-hand side *deny* when the nonce fails to verify?
     *
     * The negation is the whole rule, and matching without it inverted the
     * answer on every case in the corpus:
     *
     * ```php
     * if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'x' ) ) {
     *     save();          // safe: no nonce, conjunction false, nothing happens
     * }
     *
     * if ( isset( $_REQUEST['nonce'] ) && ! wp_verify_nonce( $_REQUEST['nonce'], 'x' ) ) {
     *     wp_die();        // bypassable: no nonce, conjunction false, no wp_die
     * }
     * ```
     *
     * Both spell "check the nonce if one was supplied". Only the second turns
     * that into a way in, because only the second is the guard that stops the
     * request. Seven plugins wrote the first and were told their CSRF check did
     * not work.
     *
     * Parity, not presence: `! ( isset( $x ) && verify( $x ) )` is the same safe
     * shape written inside a negation, and Jetpack's disconnect handler is
     * exactly that.
     *
     * Compared by printed source rather than by node identity, because
     * `$_REQUEST['nonce']` in the isset() and in the call are different nodes
     * saying the same thing. Crude, and exact enough for a shape this specific.
     */
    private function deniesOnFailure(Node\Expr $node, string $guarded, Standard $printer, bool $negated): bool
    {
        if ($node instanceof Node\Expr\BooleanNot) {
            return $this->deniesOnFailure($node->expr, $guarded, $printer, ! $negated);
        }

        // `false === wp_verify_nonce( … )` is the same denial spelled out.
        if (
            $node instanceof Node\Expr\BinaryOp\Identical
            || $node instanceof Node\Expr\BinaryOp\Equal
        ) {
            foreach ([[$node->left, $node->right], [$node->right, $node->left]] as [$operand, $other]) {
                if (self::isFalseLiteral($operand)) {
                    return $this->deniesOnFailure($other, $guarded, $printer, ! $negated);
                }
            }
        }

        if ($node instanceof Node\Expr\BinaryOp\BooleanAnd || $node instanceof Node\Expr\BinaryOp\BooleanOr) {
            return $this->deniesOnFailure($node->left, $guarded, $printer, $negated)
                || $this->deniesOnFailure($node->right, $guarded, $printer, $negated);
        }

        return $negated && $this->verifiesSameValue($node, $guarded, $printer);
    }

    /**
     * Does a request without the nonce get stopped anyway?
     *
     * First by the condition the conjunction sits in, then by an earlier
     * branch on the way out to the enclosing function. See the class comment.
     *
     * @param SplObjectStorage<Node, Node> $parents
     * @param array<Node> $ast
     */
    private function handlesAbsence(
        Node\Expr\BinaryOp\BooleanAnd $conjunction,
        string $guarded,
        SplObjectStorage $parents,
        array $ast,
        Standard $printer,
    ): bool {
        // A failed nonce makes the conjunction true. Each negation on the way
        // up flips which value of the whole condition that is.
        $condition = $conjunction;
        $failed = true;

        while (
            ($parent = self::parentOf($condition, $parents)) instanceof Node\Expr\BooleanNot
            || $parent instanceof Node\Expr\BinaryOp\BooleanAnd
            || $parent instanceof Node\Expr\BinaryOp\BooleanOr
            || $parent instanceof Node\Expr\BinaryOp\LogicalAnd
            || $parent instanceof Node\Expr\BinaryOp\LogicalOr
        ) {
            if ($parent instanceof Node\Expr\BooleanNot) {
                $failed = ! $failed;
            }

            $condition = $parent;
        }

        if ($this->whenAbsent($condition, $guarded, $printer) === $failed) {
            return true;
        }

        return $this->exitsEarlier($condition, $guarded, $parents, $ast, $printer);
    }

    /**
     * Is there a branch before this node, in the same function, that is
     * certainly taken when the nonce is missing and never falls through?
     *
     * @param SplObjectStorage<Node, Node> $parents
     * @param array<Node> $ast
     */
    private function exitsEarlier(
        Node $node,
        string $guarded,
        SplObjectStorage $parents,
        array $ast,
        Standard $printer,
    ): bool {
        $child = $node;
        // A throw inside a try can be caught, and the code after the try
        // still runs, so from there on only a return or an exit leaves.
        $caught = false;

        while (true) {
            $parent = self::parentOf($child, $parents);
            $siblings = $parent === null ? $ast : self::siblingList($parent, $child);
            $caught = $caught || $parent instanceof Node\Stmt\TryCatch;

            foreach ($siblings as $sibling) {
                if ($sibling === $child) {
                    break;
                }

                if (
                    $sibling instanceof Node\Stmt\If_
                    && $this->whenAbsent($sibling->cond, $guarded, $printer) === true
                    && self::neverFallsThrough($sibling->stmts, $caught)
                ) {
                    return true;
                }
            }

            if (
                $parent instanceof Node\Stmt\If_
                && ($child instanceof Node\Stmt\ElseIf_ || $child instanceof Node\Stmt\Else_)
                && $this->earlierBranchExits($parent, $child, $guarded, $printer, $caught)
            ) {
                return true;
            }

            // A closure or method runs on its own schedule, so a branch
            // outside it says nothing about the request inside it.
            if ($parent === null || $parent instanceof Node\FunctionLike) {
                return false;
            }

            $child = $parent;
        }
    }

    /**
     * Is an `elseif` or `else` reached, without the nonce, only past a branch
     * that leaves?
     *
     * The branches are tried in order. One that is certainly not taken passes
     * the request on to the next. One that is certainly taken decides it. One
     * that might go either way ends the question, because the request could
     * take it and fall through.
     */
    private function earlierBranchExits(
        Node\Stmt\If_ $if,
        Node\Stmt\ElseIf_|Node\Stmt\Else_ $branch,
        string $guarded,
        Standard $printer,
        bool $caught,
    ): bool {
        foreach ([$if, ...$if->elseifs] as $earlier) {
            if ($earlier === $branch) {
                return false;
            }

            $taken = $this->whenAbsent($earlier->cond, $guarded, $printer);

            if ($taken === null) {
                return false;
            }

            if ($taken) {
                return self::neverFallsThrough($earlier->stmts, $caught);
            }
        }

        return false;
    }

    /**
     * Does this block always end by stopping the request's handler?
     *
     * A `throw` counts only when no `try` around the block can catch it.
     *
     * @param array<Node\Stmt> $body
     */
    private static function neverFallsThrough(array $body, bool $caught): bool
    {
        $statements = array_values(array_filter(
            $body,
            static fn (Node\Stmt $statement): bool => ! $statement instanceof Node\Stmt\Nop,
        ));
        $last = $statements[count($statements) - 1] ?? null;

        if ($last instanceof Node\Stmt\Return_) {
            return true;
        }

        if (! $last instanceof Node\Stmt\Expression) {
            return false;
        }

        $expression = $last->expr;

        if ($expression instanceof Node\Expr\Exit_) {
            return true;
        }

        if ($expression instanceof Node\Expr\Throw_) {
            return ! $caught;
        }

        return $expression instanceof Node\Expr\FuncCall
            && in_array(AstHelper::functionName($expression), GuardAnalyzer::NEVER_RETURN, true);
    }

    /**
     * What a condition is when the nonce is missing: true, false, or unknown.
     *
     * Only the presence tests on that exact value are known. `isset()` of it
     * is false and `empty()` of it is true. Everything else could go either
     * way, so it is null, and an unknown operand leaves `&&` and `||` unknown
     * unless the other side settles them.
     */
    private function whenAbsent(Node\Expr $node, string $guarded, Standard $printer): ?bool
    {
        if ($node instanceof Node\Expr\BooleanNot) {
            $inner = $this->whenAbsent($node->expr, $guarded, $printer);

            return $inner === null ? null : ! $inner;
        }

        if ($node instanceof Node\Expr\BinaryOp\BooleanAnd || $node instanceof Node\Expr\BinaryOp\LogicalAnd) {
            $left = $this->whenAbsent($node->left, $guarded, $printer);
            $right = $this->whenAbsent($node->right, $guarded, $printer);

            if ($left === false || $right === false) {
                return false;
            }

            return $left === true && $right === true ? true : null;
        }

        if ($node instanceof Node\Expr\BinaryOp\BooleanOr || $node instanceof Node\Expr\BinaryOp\LogicalOr) {
            $left = $this->whenAbsent($node->left, $guarded, $printer);
            $right = $this->whenAbsent($node->right, $guarded, $printer);

            if ($left === true || $right === true) {
                return true;
            }

            return $left === false && $right === false ? false : null;
        }

        // isset() of several values is false when any one of them is missing.
        if ($node instanceof Node\Expr\Isset_) {
            foreach ($node->vars as $var) {
                if ($printer->prettyPrintExpr($var) === $guarded) {
                    return false;
                }
            }

            return null;
        }

        if ($node instanceof Node\Expr\Empty_ && $printer->prettyPrintExpr($node->expr) === $guarded) {
            return true;
        }

        return null;
    }

    /**
     * Each node's parent, for the few files that need to walk upwards.
     *
     * Kept beside the tree rather than written onto it, because the AST is
     * shared with the rules that run after this one.
     *
     * @param array<Node> $ast
     *
     * @return SplObjectStorage<Node, Node>
     */
    private static function parents(array $ast): SplObjectStorage
    {
        /** @var SplObjectStorage<Node, Node> $parents */
        $parents = new SplObjectStorage();

        $visitor = new class ($parents) extends NodeVisitorAbstract {
            /** @var list<Node> */
            private array $stack = [];

            /**
             * @param SplObjectStorage<Node, Node> $parents
             */
            public function __construct(private readonly SplObjectStorage $parents)
            {
            }

            public function enterNode(Node $node): null
            {
                $parent = $this->stack[count($this->stack) - 1] ?? null;

                if ($parent !== null) {
                    $this->parents[$node] = $parent;
                }

                $this->stack[] = $node;

                return null;
            }

            public function leaveNode(Node $node): null
            {
                array_pop($this->stack);

                return null;
            }
        };

        (new NodeTraverser($visitor))->traverse($ast);

        return $parents;
    }

    /**
     * @param SplObjectStorage<Node, Node> $parents
     */
    private static function parentOf(Node $node, SplObjectStorage $parents): ?Node
    {
        return $parents->contains($node) ? $parents[$node] : null;
    }

    /**
     * The statements, in the parent's body, that hold the child.
     *
     * Every block that runs in order keeps its body in `stmts`: a function,
     * an `if` branch, a loop, a `case`, a `try`. Anything else, an `elseif`
     * in its `if` or a `catch` in its `try`, is not in order with what sits
     * beside it, and gets nothing.
     *
     * @return array<mixed>
     */
    private static function siblingList(Node $parent, Node $child): array
    {
        if (! property_exists($parent, 'stmts') || ! is_array($parent->stmts)) {
            return [];
        }

        return in_array($child, $parent->stmts, true) ? $parent->stmts : [];
    }

    private static function isFalseLiteral(Node\Expr $node): bool
    {
        return $node instanceof Node\Expr\ConstFetch && strtolower($node->name->toString()) === 'false';
    }

    /**
     * Does this expression verify a nonce read from exactly that value?
     */
    private function verifiesSameValue(Node\Expr $right, string $guarded, Standard $printer): bool
    {
        foreach ((new NodeFinder())->findInstanceOf([$right], Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name === null || ! in_array($name, self::VERIFIERS, true)) {
                continue;
            }

            foreach ($call->getArgs() as $argument) {
                if ($printer->prettyPrintExpr($argument->value) === $guarded) {
                    return true;
                }
            }
        }

        return false;
    }
}
