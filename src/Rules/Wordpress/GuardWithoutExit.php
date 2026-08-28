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

/**
 * A failed check that redirects and then carries on anyway.
 *
 * ```php
 * if ( ! current_user_can( 'manage_options' ) ) {
 *     wp_safe_redirect( admin_url( 'tools.php' ) );   // returns
 * }
 *
 * foreach ( $_POST['option'] as $name => $value )
 *     update_option( $name, $value );                 // still runs
 * ```
 *
 * `wp_redirect()` sends a Location header and returns. It does not stop the
 * script. The browser follows the redirect and never renders the response, so
 * the page looks like it worked — and the body of the request executed in full
 * before that response was sent.
 *
 * This is the most consequential bug in the WordPress plugin team's
 * intentionally vulnerable plugin: it is what turns a failed capability check
 * into no capability check, and the reason issue 11 in that file is reachable
 * at all. Core's own handbook says to call `exit` after every redirect.
 *
 * ## Kept narrow on purpose
 *
 * Only a redirect that is the last statement of an `if` body, where the
 * enclosing block continues afterwards. A redirect at the end of a function is
 * not reported: control returns to a caller this rule cannot see, and guessing
 * would flood the corpus with findings on code that is fine.
 */
final class GuardWithoutExit implements StructuralRule
{
    private const RULE = 'wp.authz.guard-without-exit';

    private const REDIRECTS = ['wp_redirect', 'wp_safe_redirect'];

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

        foreach ($this->blocks($file) as $statements) {
            $findings = [...$findings, ...$this->scanBlock($statements, $file, $registry)];
        }

        return $findings;
    }

    /**
     * Every list of statements in the file that can have something after it.
     *
     * @return list<list<Node\Stmt>>
     */
    private function blocks(ParsedFile $file): array
    {
        $blocks = [self::statements($file->ast())];
        $finder = new NodeFinder();

        foreach ([Node\Stmt\ClassMethod::class, Node\Stmt\Function_::class, Node\Expr\Closure::class] as $class) {
            foreach ($finder->findInstanceOf($file->ast(), $class) as $node) {
                /** @var Node\Stmt\ClassMethod|Node\Stmt\Function_|Node\Expr\Closure $node */
                if ($node->stmts !== null) {
                    $blocks[] = self::statements($node->stmts);
                }
            }
        }

        return $blocks;
    }

    /**
     * Statements, with the parser's comment placeholders dropped.
     *
     * php-parser emits a `Nop` for a comment that trails the last statement of
     * a block, so `wp_safe_redirect( $url ); // bail` ends in a Nop and a rule
     * that looks at the last statement sees the comment instead of the
     * redirect. A fixture written with the suite's own `wp-taint-expect`
     * annotation on that line is what surfaced it, which means the rule would
     * have missed every commented guard in the wild.
     *
     * @param array<array-key, Node> $nodes
     *
     * @return list<Node\Stmt>
     */
    private static function statements(array $nodes): array
    {
        return array_values(array_filter(
            $nodes,
            static fn (Node $node): bool => $node instanceof Node\Stmt && ! $node instanceof Node\Stmt\Nop,
        ));
    }

    /**
     * @param list<Node\Stmt> $statements
     *
     * @return list<Finding>
     */
    private function scanBlock(array $statements, ParsedFile $file, Registry $registry): array
    {
        $findings = [];
        $count = count($statements);

        foreach ($statements as $index => $statement) {
            // Nothing follows, so nothing falls through into anything.
            if ($index === $count - 1) {
                continue;
            }

            if (! $statement instanceof Node\Stmt\If_ || $statement->else !== null || $statement->elseifs !== []) {
                continue;
            }

            $redirect = $this->trailingRedirect(self::statements($statement->stmts));

            if ($redirect === null) {
                continue;
            }

            $name = AstHelper::functionName($redirect);

            $findings[] = StructuralFinding::at(
                $redirect,
                $file,
                $registry,
                self::RULE,
                Severity::High,
                sprintf(
                    '%s() sends a Location header and returns; it does not stop the script. The check fails, the '
                        . 'redirect is queued, and the statements after this block run anyway — so failing the '
                        . 'check does not prevent the work it guards.',
                    $name ?? 'wp_redirect',
                ),
                $name ?? 'wp_redirect',
            );
        }

        return $findings;
    }

    /**
     * The redirect call ending this block, when nothing stops execution after it.
     *
     * @param list<Node\Stmt> $statements
     */
    private function trailingRedirect(array $statements): ?Node\Expr\FuncCall
    {
        $last = $statements[count($statements) - 1] ?? null;

        if ($last === null) {
            return null;
        }

        // exit, die, return, throw and continue all end the guard properly.
        if (! $last instanceof Node\Stmt\Expression) {
            return null;
        }

        $expression = $last->expr;

        if (! $expression instanceof Node\Expr\FuncCall) {
            return null;
        }

        $name = AstHelper::functionName($expression);

        return $name !== null && in_array($name, self::REDIRECTS, true) ? $expression : null;
    }
}
