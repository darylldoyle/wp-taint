<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\CapabilityScope;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Block;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Is every path to this sink through a check that entitles the caller to the
 * object being operated on?
 *
 * The question behind `wp.authz.object-id-from-request`. A request-chosen id
 * reaching `wp_delete_post()` is only a finding when nothing dominating the
 * sink ties the *caller* to the *row*: an object-scoped meta capability with
 * the id in hand, or a site-wide grant that entitles cross-object action.
 *
 * ```php
 * if ( ! current_user_can( 'delete_post', $id ) ) {   // discharges it
 *     wp_die();
 * }
 * wp_delete_post( $id );
 *
 * if ( ! current_user_can( 'edit_posts' ) ) {          // does not — a role
 *     wp_die();                                        // says nothing about
 * }                                                    // whose row this is
 * wp_delete_post( $id );
 * ```
 *
 * Same skeleton as {@see GuardAnalyzer} — dominance over the block graph, a
 * predicate read off the branch edge — and a different predicate: that one asks
 * what the *value* can still contain, this one what the *caller* has been
 * proved entitled to. An id has no payload for a character-class guard to
 * remove, which is why the two cannot share a predicate.
 *
 * ## Which checks count
 *
 * The capability functions themselves are read precisely: the literal
 * capability is looked up in the `[[capabilities]]` catalogue, an object-scoped
 * one needs its object argument present, a role-scoped one never counts. Two
 * deliberate generosities, both on the suppressing side because a false
 * positive here costs more than a documented miss:
 *
 * - A capability the catalogue does not know — a plugin's own — counts. Plugin
 *   capabilities are typically minted for administrators.
 * - A dominating branch on a *helper* counts when the call graph shows the
 *   helper reaching an entitlement primitive, or, for a call the graph cannot
 *   resolve, when its name reads like a permission check. Real handlers wrap
 *   their checks constantly, and the wrapper's capability is out of reach.
 *
 * Nonce checks never count, whatever their spelling: a nonce proves the
 * request came from a form this site rendered, and a subscriber holds a valid
 * nonce for every form they can see. Entitlement is the whole question here.
 */
final class CapabilityGuard
{
    /**
     * Capability function => [capability argument, object argument].
     *
     * From core's signatures. `current_user_can( $capability, $object )`;
     * the others take a user, blog or post first.
     */
    private const CHECKERS = [
        'current_user_can' => [0, 1],
        'user_can' => [1, 2],
        'author_can' => [1, 2],
        'current_user_can_for_blog' => [1, 2],
    ];

    /** Site-wide by definition, no capability argument to inspect. */
    private const SUPER = ['is_super_admin'];

    /**
     * Name fragments that read as a permission check, for calls the graph
     * cannot speak for. `nonce`, `verify` and `referer` are deliberately
     * absent: those prove intent, and intent is not the question.
     */
    private const CHECK_FRAGMENTS = ['can', 'cap', 'permission', 'allowed', 'authori', 'access'];

    /** How far to walk from a helper before giving up, matching the authorization rules. */
    private const MAX_DEPTH = 6;

    /** Dominators, per function. */
    private ?BlockDominators $dominators = null;

    /** @var SplObjectStorage<Op, Block>|null the block each op of the current function sits in */
    private ?SplObjectStorage $blockOf = null;

    /** @var SplObjectStorage<Block, null>|null blocks {@see isEntitled()} is part-way through */
    private ?SplObjectStorage $asking = null;

    public function __construct(
        private readonly Registry $registry,
        private readonly ?CallGraph $callGraph,
    ) {
    }

    /**
     * Start a new function. Dominance is a property of one block graph.
     *
     * @param list<Block> $blocks
     */
    public function forFunction(array $blocks): void
    {
        $this->dominators = BlockDominators::compute($blocks);
        $this->blockOf = new SplObjectStorage();

        foreach ($blocks as $block) {
            foreach ([...$block->phi, ...$block->children] as $op) {
                $this->blockOf[$op] = $block;
            }
        }
    }

    /**
     * Does an entitling check dominate this block?
     *
     * Shares {@see GuardAnalyzer}'s one deliberate looseness: the entitled edge
     * must feed a block every path passes through, but a guard whose failure
     * arm falls through instead of exiting is still credited.
     * {@see \Enshrined\WpTaint\Rules\Wordpress\GuardWithoutExit} reports that
     * shape in its own right.
     */
    public function isEntitled(?Block $block): bool
    {
        if ($block === null || $this->dominators === null || ! $this->dominators->covers($block)) {
            return false;
        }

        // A phi's inputs are asked about in turn, and in a loop one of them can
        // lead back here. A block already being asked about is not entitled on
        // that path, which is the answer that cannot suppress a finding.
        $this->asking ??= new SplObjectStorage();

        if ($this->asking->contains($block)) {
            return false;
        }

        $this->asking->attach($block);

        try {
            return $this->entitledByDominator($block);
        } finally {
            $this->asking->detach($block);
        }
    }

    private function entitledByDominator(Block $block): bool
    {
        if ($this->dominators === null) {
            return false;
        }

        $dominating = $this->dominators->of($block);

        foreach ($dominating as $candidate) {
            foreach ($candidate->parents as $parent) {
                $terminal = $parent->children[count($parent->children) - 1] ?? null;

                if ($terminal instanceof Op\Stmt\JumpIf && $this->entitlesOnEdge($terminal, $candidate)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Does this permission callback allow a request only once the caller is
     * entitled?
     *
     * WordPress runs a REST route's callback only when its
     * `permission_callback` returns something truthy, so a callback whose
     * every allowing `return` sits behind an entitling check hands the route
     * its entitlement. Each `return` must be one of:
     *
     * - in a block an entitling check dominates, as in the guard-clause shape
     *   `if ( ! current_user_can( 'delete_post', $id ) ) { return false; }
     *   return true;`
     * - the result of an entitling check, `return current_user_can( … );`,
     *   directly or through assignments, or a phi every one of whose values
     *   qualifies, which is how `a && b` reaches a return
     * - a refusal: `false`, `null`, `0`, `''`, or a `WP_Error`
     *
     * The capability rules are the ones a check in the handler meets: a role
     * capability entitles nothing, an object capability needs its object.
     * A callback with no `return` at all allows nothing and entitles nothing.
     */
    public function permitsOnlyWhenEntitled(FunctionContext $permission): bool
    {
        $blocks = BlockOrder::of($permission->func->cfg);

        if ($blocks === []) {
            return false;
        }

        $saved = [$this->dominators, $this->blockOf];
        $this->forFunction($blocks);
        /** @var SplObjectStorage<Op, Block> $blockOf */
        $blockOf = $this->blockOf ?? new SplObjectStorage();

        try {
            $returns = 0;

            foreach ($blocks as $block) {
                foreach ($block->children as $op) {
                    if (! $op instanceof Op\Terminal\Return_) {
                        continue;
                    }

                    $returns++;

                    if ($this->isEntitled($block)) {
                        continue;
                    }

                    if ($op->expr !== null && $this->isProvenError($op->expr, $block)) {
                        continue;
                    }

                    if ($op->expr === null || ! $this->allowsOnlyWhenEntitled($op->expr, $blockOf)) {
                        return false;
                    }
                }
            }

            return $returns > 0;
        } finally {
            [$this->dominators, $this->blockOf] = $saved;
        }
    }

    /**
     * @param SplObjectStorage<Op, Block> $blockOf
     */
    private function allowsOnlyWhenEntitled(Operand $value, SplObjectStorage $blockOf, int $depth = 0): bool
    {
        if ($value instanceof Operand\Literal) {
            return ! $value->value;
        }

        if ($depth > self::MAX_DEPTH) {
            return false;
        }

        $definition = OperandHelper::definingOp($value);

        if ($definition === null) {
            return false;
        }

        if ($blockOf->contains($definition) && $this->isEntitled($blockOf[$definition])) {
            return true;
        }

        if ($definition instanceof Op\Expr\Assign) {
            return $this->allowsOnlyWhenEntitled($definition->expr, $blockOf, $depth + 1);
        }

        if ($definition instanceof Op\Phi) {
            foreach ($definition->vars as $var) {
                if (! $var instanceof Operand || ! $this->allowsOnlyWhenEntitled($var, $blockOf, $depth + 1)) {
                    return false;
                }
            }

            return $definition->vars !== [];
        }

        if ($definition instanceof Op\Expr\New_) {
            $class = OperandHelper::literalString($definition->class);

            return $class !== null && strtolower(ltrim($class, '\\')) === 'wp_error';
        }

        if ($definition instanceof Op\Expr\ConstFetch) {
            $name = OperandHelper::literalString($definition->name);

            return $name !== null && in_array(strtolower(ltrim($name, '\\')), ['false', 'null'], true);
        }

        return $this->entitles($definition);
    }

    /**
     * `if ( is_wp_error( $review ) ) { return $review; }`: the value returned
     * is an error on every path here, so returning it refuses the request.
     */
    private function isProvenError(Operand $value, Block $block): bool
    {
        if ($this->dominators === null || ! $this->dominators->covers($block)) {
            return false;
        }

        $name = OperandHelper::variableName($value);

        $dominating = $this->dominators->of($block);

        foreach ($dominating as $candidate) {
            foreach ($candidate->parents as $parent) {
                $jump = $parent->children[count($parent->children) - 1] ?? null;

                if (! $jump instanceof Op\Stmt\JumpIf || $jump->if !== $candidate) {
                    continue;
                }

                $check = OperandHelper::definingOp($jump->cond);

                if (
                    ($check instanceof Op\Expr\FuncCall || $check instanceof Op\Expr\NsFuncCall)
                    && strtolower(ltrim(OperandHelper::literalString($check->name) ?? '', '\\')) === 'is_wp_error'
                ) {
                    $checked = $check->args[0] ?? null;

                    if (
                        $checked === $value || ($name !== null && $checked instanceof Operand
                        && OperandHelper::variableName($checked) === $name)
                    ) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Does this branch prove entitlement on the edge we arrived by?
     *
     * A check entitles when it *passes*, so the wanted edge is the true edge,
     * flipped once per `BooleanNot` between the call and the condition —
     * `if ( ! current_user_can( … ) ) { wp_die(); }` entitles the else edge.
     */
    private function entitlesOnEdge(Op\Stmt\JumpIf $jump, Block $arrivedAt): bool
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

            // `if ( ! current_user_can( … ) || $other ) { return; }` branches
            // on a phi: `true` when the check failed, `$other` otherwise. The
            // value the phi has on the edge we arrived by rules some of its
            // inputs out, and every input still possible must have come from
            // an entitled block.
            if ($definition instanceof Op\Phi) {
                $value = ($arrivedAt === $jump->if) === $positive;

                return $this->phiProvesEntitled($definition, $value);
            }

            if ($definition === null || ! $this->entitles($definition)) {
                return false;
            }

            $wanted = $positive ? $jump->if : $jump->else;

            return $wanted === $arrivedAt;
        }
    }

    /**
     * Whether a phi that holds `$value` could only have got it by a path the
     * caller was entitled on.
     */
    private function phiProvesEntitled(Op\Phi $phi, bool $value): bool
    {
        $possible = 0;

        foreach ($phi->vars as $var) {
            if (! $var instanceof Operand) {
                return false;
            }

            if ($var instanceof Operand\Literal) {
                // A literal that cannot be `$value` is a path not taken.
                if ((bool) $var->value !== $value) {
                    continue;
                }

                return false;
            }

            $possible++;
            $definition = OperandHelper::definingOp($var);

            if (
                $definition === null
                || $this->blockOf === null
                || ! $this->blockOf->contains($definition)
                || ! $this->isEntitled($this->blockOf[$definition])
            ) {
                return false;
            }
        }

        return $possible > 0;
    }

    private function entitles(Op $definition): bool
    {
        if ($definition instanceof Op\Expr\FuncCall || $definition instanceof Op\Expr\NsFuncCall) {
            $name = OperandHelper::literalString($definition->name);

            if ($name === null) {
                return false;
            }

            $name = strtolower(ltrim($name, '\\'));

            if (in_array($name, self::SUPER, true)) {
                return true;
            }

            if (isset(self::CHECKERS[$name])) {
                return $this->capabilityEntitles($definition, ...self::CHECKERS[$name]);
            }

            return $this->helperEntitles($name);
        }

        if ($definition instanceof Op\Expr\StaticCall) {
            $class = OperandHelper::literalString($definition->class);
            $method = OperandHelper::literalString($definition->name);

            if ($method === null) {
                return false;
            }

            if ($class !== null && $this->helperEntitles(strtolower(ltrim($class, '\\') . '::' . $method))) {
                return true;
            }

            return $this->looksLikeCheck($method);
        }

        if ($definition instanceof Op\Expr\MethodCall) {
            $method = OperandHelper::literalString($definition->name);

            // `$user->has_cap( 'edit_post' )` is current_user_can() for a user
            // in hand; the receiver's class is out of reach here, so the name
            // carries it.
            if ($method !== null && strtolower($method) === 'has_cap') {
                return $this->capabilityEntitles($definition, 0, 1);
            }

            return $method !== null && $this->looksLikeCheck($method);
        }

        return false;
    }

    /**
     * The precise half: a capability function with its arguments readable.
     */
    private function capabilityEntitles(
        Op\Expr\FuncCall|Op\Expr\NsFuncCall|Op\Expr\MethodCall $call,
        int $capabilityArgument,
        int $objectArgument,
    ): bool {
        $arguments = array_values(array_filter(
            $call->args,
            static fn (mixed $argument): bool => $argument instanceof Operand,
        ));

        $capability = isset($arguments[$capabilityArgument])
            ? OperandHelper::literalString($arguments[$capabilityArgument])
            : null;

        // A computed capability could be anything, including an object-scoped
        // one paired with the id below it. Suppressing is the direction that
        // cannot invent a finding.
        if ($capability === null) {
            return true;
        }

        return match ($this->registry->capabilityScope($capability)) {
            CapabilityScope::Site, null => true,
            CapabilityScope::Object => isset($arguments[$objectArgument]),
            CapabilityScope::Role => false,
        };
    }

    /**
     * The generous half: a helper whose body the graph can vouch for, or
     * failing that a name that reads as a check.
     */
    private function helperEntitles(string $key): bool
    {
        if ($this->callGraph !== null && $this->callGraph->knows($key)) {
            return $this->callGraph->reaches($key, $this->registry->entitlementChecks(), self::MAX_DEPTH);
        }

        return $this->looksLikeCheck($key);
    }

    private function looksLikeCheck(string $name): bool
    {
        $lower = strtolower($name);

        foreach (self::CHECK_FRAGMENTS as $fragment) {
            if (str_contains($lower, $fragment)) {
                return true;
            }
        }

        return false;
    }
}
