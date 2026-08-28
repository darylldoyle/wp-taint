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

/**
 * A nonce created or verified without naming an action.
 *
 * Every nonce function takes an action and defaults it to -1. A -1 nonce is
 * valid, so the check passes and the code looks defended; it is just the *same*
 * nonce everywhere. Any other -1 form on the site — core's, another plugin's —
 * yields a token this check will accept, so the nonce stops being tied to this
 * operation and stops being CSRF protection.
 *
 * This is the first of the two nonce bugs in the WordPress plugin team's
 * intentionally vulnerable plugin, where `wp_nonce_field()` and
 * `check_admin_referer()` are both called bare.
 *
 * ## Why it is only medium
 *
 * A shared nonce is a much weaker defence than a named one and a much stronger
 * one than none: the attacker still has to source a valid token for the victim's
 * session. Reported so it can be fixed, not so it can be panicked about.
 */
final class NonceWithoutAction implements StructuralRule
{
    private const RULE = 'wp.csrf.nonce-without-action';

    /**
     * Function name => the argument index the action belongs in.
     *
     * From core's own signatures. `wp_verify_nonce( $nonce, $action )` and
     * `wp_nonce_url( $url, $action )` take it second; the rest take it first.
     */
    private const ACTION_ARGUMENT = [
        'wp_nonce_field' => 0,
        'wp_create_nonce' => 0,
        'check_admin_referer' => 0,
        'check_ajax_referer' => 0,
        'wp_verify_nonce' => 1,
        'wp_nonce_url' => 1,
    ];

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

        foreach (AstHelper::findAll($file->ast(), Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name === null || ! isset(self::ACTION_ARGUMENT[$name])) {
                continue;
            }

            $argument = AstHelper::argument($call, self::ACTION_ARGUMENT[$name]);

            if ($argument !== null && ! $this->isDefaultAction($argument)) {
                continue;
            }

            $findings[] = StructuralFinding::at(
                $call,
                $file,
                $registry,
                self::RULE,
                Severity::Medium,
                sprintf(
                    '%s() was called without an action, so it uses the default -1 nonce. That token is shared '
                        . 'with every other bare nonce on the site, including core\'s, so it does not tie the '
                        . 'request to this operation.',
                    $name,
                ),
                $name,
            );
        }

        return $findings;
    }

    /**
     * An explicit -1 is the same bug as omitting it, and reads as deliberate,
     * which makes it worth naming rather than passing over.
     */
    private function isDefaultAction(Node $argument): bool
    {
        if ($argument instanceof Node\Expr\UnaryMinus && $argument->expr instanceof Node\Scalar\Int_) {
            return $argument->expr->value === 1;
        }

        return $argument instanceof Node\Scalar\String_ && $argument->value === '-1';
    }
}
