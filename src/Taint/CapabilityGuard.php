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

    /** @var SplObjectStorage<Block, SplObjectStorage<Block, true>>|null dominators, per function */
    private ?SplObjectStorage $dominators = null;

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
        $this->dominators = $blocks === [] ? null : BlockDominators::compute($blocks);
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
        if ($block === null || $this->dominators === null || ! $this->dominators->contains($block)) {
            return false;
        }

        /** @var SplObjectStorage<Block, true> $dominating */
        $dominating = $this->dominators[$block];

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

            if ($definition === null || ! $this->entitles($definition)) {
                return false;
            }

            $wanted = $positive ? $jump->if : $jump->else;

            return $wanted === $arrivedAt;
        }
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
