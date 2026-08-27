<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Cfg\SourceMap;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Fingerprint;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\HookCallbackResolver;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * An AJAX handler with neither a capability check nor a nonce check.
 *
 * `wp_ajax_*` is reachable by any logged-in user, including a subscriber;
 * `wp_ajax_nopriv_*` is reachable by anyone at all. Neither hook implies any
 * authorization, and the check has to be written by hand in the callback.
 */
final class MissingAjaxCapabilityCheck implements StructuralRule
{
    private const RULE = 'wp.authz.ajax-missing-check';

    private const AUTHORIZATION_FUNCTIONS = [
        'current_user_can',
        'current_user_can_for_blog',
        'check_ajax_referer',
        'check_admin_referer',
        'wp_verify_nonce',
        'is_user_logged_in',
        'user_can',
        'is_super_admin',
        'auth_redirect',
        'validate_ajax_nonce',
    ];

    /**
     * Deliberately absent: `wp_die()`, `wp_get_current_user()` and
     * `get_current_user_id()`. All three appear constantly in handlers that
     * have no authorization at all — `wp_die('ok')` is how a handler *ends*,
     * not how it checks anything — and accepting them silently suppressed a
     * real finding on the first run of the fixture suite.
     */

    public function id(): string
    {
        return self::RULE;
    }

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array
    {
        $resolver = new HookCallbackResolver($file->ast);
        $findings = [];

        foreach (AstHelper::findAll($file->ast, Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name !== 'add_action') {
                continue;
            }

            $hook = AstHelper::stringValue(AstHelper::argument($call, 0));

            if ($hook === null || ! str_starts_with($hook, 'wp_ajax_')) {
                continue;
            }

            $callback = AstHelper::argument($call, 1);

            if ($callback === null) {
                continue;
            }

            $resolved = $resolver->resolve($callback, $this->enclosingClass($file, $call));

            if ($resolved === null) {
                $context->recordUnresolvedHook(
                    $hook,
                    $file->relativePath,
                    $call->getStartLine(),
                    'callback could not be resolved to a function body',
                );

                continue;
            }

            if ($this->hasAuthorizationCheck($resolved['stmts'])) {
                continue;
            }

            $findings[] = $this->finding($call, $hook, $resolved['description'], $file, $registry);
        }

        return $findings;
    }

    /**
     * @param list<Node\Stmt> $stmts
     */
    private function hasAuthorizationCheck(array $stmts): bool
    {
        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name !== null && in_array($name, self::AUTHORIZATION_FUNCTIONS, true)) {
                return true;
            }
        }

        // `$this->verify_request()` and friends. A method call whose name reads
        // like a check is accepted: the alternative is a false positive on
        // every codebase that factors its checks into a helper, and a false
        // positive on an authorization rule is exactly the kind that gets the
        // tool muted.
        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            if ($this->looksLikeCheck($call->name->toString())) {
                return true;
            }
        }

        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Expr\StaticCall::class) as $call) {
            if (! $call instanceof Node\Expr\StaticCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            if ($this->looksLikeCheck($call->name->toString())) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeCheck(string $method): bool
    {
        $lower = strtolower($method);

        $needles = ['can', 'capab', 'permission', 'nonce', 'referer', 'referrer', 'authori', 'authenticat', 'verify'];

        foreach ($needles as $needle) {
            if (str_contains($lower, $needle)) {
                return true;
            }
        }

        return false;
    }

    private function enclosingClass(ParsedFile $file, Node $node): ?string
    {
        $line = $node->getStartLine();

        foreach (AstHelper::findAll($file->ast, Node\Stmt\ClassLike::class) as $classLike) {
            if (! $classLike instanceof Node\Stmt\ClassLike || $classLike->name === null) {
                continue;
            }

            if ($classLike->getStartLine() <= $line && $line <= $classLike->getEndLine()) {
                return $classLike->namespacedName?->toString() ?? $classLike->name->toString();
            }
        }

        return null;
    }

    private function finding(
        Node\Expr\FuncCall $call,
        string $hook,
        string $callbackDescription,
        ParsedFile $file,
        Registry $registry,
    ): Finding {
        $line = $call->getStartLine();
        $column = self::column($call, $file->sourceMap);
        $snippet = trim($file->sourceMap->line($line));

        $reach = str_starts_with($hook, 'wp_ajax_nopriv_')
            ? 'Registered on a nopriv hook, so it is reachable by unauthenticated visitors.'
            : 'Registered on an authenticated AJAX hook, so it is reachable by any logged-in user, including a '
                . 'subscriber.';

        $step = new TraceStep(
            TraceVerb::Sink,
            $file->relativePath,
            $line,
            $column,
            null,
            $snippet,
            sprintf(
                '%s The callback (%s) contains no capability or nonce check.',
                $reach,
                $callbackDescription,
            ),
            TaintSet::of(TaintKind::Authz),
        );

        return new Finding(
            self::RULE,
            $registry->rule(self::RULE),
            str_starts_with($hook, 'wp_ajax_nopriv_') ? Severity::High : Severity::Medium,
            TaintKind::Authz,
            $file->relativePath,
            $line,
            $column,
            null,
            $registry->ruleMessage(self::RULE),
            [$step],
            Fingerprint::compute(self::RULE, $file->relativePath, $hook, $snippet),
        );
    }

    private static function column(Node $node, SourceMap $sourceMap): int
    {
        if (! $node->hasAttribute('startFilePos')) {
            return 0;
        }

        $offset = $node->getAttribute('startFilePos');

        return is_int($offset) ? $sourceMap->positionAt($offset)['column'] : 0;
    }
}
