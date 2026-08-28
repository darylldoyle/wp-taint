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
use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;

/**
 * A nonce check that an attacker skips by omitting the nonce.
 *
 * ```php
 * if ( isset( $_REQUEST['nonce'] ) && ! wp_verify_nonce( $_REQUEST['nonce'], 'x' )
 *     || ! current_user_can( 'manage_options' ) ) {
 * ```
 *
 * Send no `nonce` parameter at all and `isset()` is false, so the conjunction is
 * false and the nonce is never verified. The guard reads as "check the nonce if
 * one was supplied", which is the same as not checking it: an attacker chooses
 * what to supply.
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

        foreach (AstHelper::findAll($file->ast(), Node\Expr\BinaryOp\BooleanAnd::class) as $node) {
            if (! $node instanceof Node\Expr\BinaryOp\BooleanAnd) {
                continue;
            }

            $guarded = $this->issetOperand($node->left, $printer);

            if ($guarded === null) {
                continue;
            }

            if (! $this->verifiesSameValue($node->right, $guarded, $printer)) {
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
     * Does the right-hand side verify a nonce read from exactly that value?
     *
     * Compared by printed source rather than by node identity, because
     * `$_REQUEST['nonce']` in the isset() and in the call are different nodes
     * saying the same thing. Crude, and exact enough for a shape this specific.
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
