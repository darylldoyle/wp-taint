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
 * A handler reached through a hook that carries no authorization of its own.
 *
 * `wp_ajax_*` and `admin_post_*` are the same shape: WordPress maps a request
 * parameter to a callback and runs it. Neither hook implies the caller may do
 * what the callback does, and the `_nopriv` variants do not even imply a
 * logged-in user. The check has to be written by hand in the callback.
 *
 * ## What counts as a check
 *
 * Walking the call graph from the callback, to a bounded depth, looking for one
 * of the `[[authorization]]` primitives in the catalogue. That is what credits
 * a helper for the right reason: `acf_verify_ajax()` counts because it calls
 * `wp_verify_nonce`, which we can see.
 *
 * The name heuristic it replaced accepted any call containing `can`, `nonce`,
 * `verify` and six other fragments. It credited `acf_verify_ajax()` by accident
 * and would have credited `$this->can_haz_cheeseburger()` too. It survives only
 * as a last resort for a callback that will not resolve, and findings that rest
 * on it are marked imprecise so they can be filtered out.
 *
 * ## Why this is a base class
 *
 * The AJAX rule existed first and the admin_post_ rule is the same walk with a
 * different prefix. The intentionally vulnerable plugin the WordPress plugin
 * team publishes has its delete handler on `admin_post_dvp_delete_log` with no
 * capability check at all, and we missed it purely because nobody had written
 * the second registrar down.
 */
abstract class HookHandlerAuthorization implements StructuralRule
{
    /**
     * How far to walk from the callback before giving up.
     *
     * A cost control, not a correctness one. A capability check six helpers
     * below the handler is not something a reviewer would credit at a glance
     * either, and the walk reports an incomplete answer rather than a clean one
     * when it stops early.
     */
    protected const MAX_DEPTH = 6;

    /** The rule this family reports. */
    abstract protected function ruleId(): string;

    /**
     * Which checks this hook family will accept as sufficient.
     *
     * @return list<string>
     */
    abstract protected function acceptedChecks(Registry $registry): array;

    /**
     * Hook name prefixes this rule claims.
     *
     * @return list<string>
     */
    abstract protected function hookPrefixes(): array;

    /** How the hook exposes the callback, for the trace step. */
    abstract protected function reachDescription(string $hook): string;

    abstract protected function severityFor(string $hook): Severity;

    public function id(): string
    {
        return $this->ruleId();
    }

    private function claims(string $hook): bool
    {
        foreach ($this->hookPrefixes() as $prefix) {
            if (str_starts_with($hook, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array
    {
        $resolver = new HookCallbackResolver($file->ast());
        $findings = [];

        foreach (AstHelper::findAll($file->ast(), Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name !== 'add_action') {
                continue;
            }

            $hook = AstHelper::stringValue(AstHelper::argument($call, 0));

            if ($hook === null || ! $this->claims($hook)) {
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

            $verdict = $this->checkVerdict($resolved, $registry, $context);

            if ($verdict['checked']) {
                continue;
            }

            $findings[] = $this->finding(
                $call,
                $hook,
                $resolved['description'],
                $file,
                $registry,
                ! $verdict['certain'],
            );
        }

        return $findings;
    }

    /**
     * Did this callback check anything, and do we actually know?
     *
     * Two separate questions. A callback that resolves and whose reachable
     * subgraph contains no primitive is a finding we can stand behind. One that
     * did not resolve, or whose walk ran into a call the engine could not
     * follow, falls back to the name heuristic and the finding is marked
     * imprecise.
     *
     * @param array{stmts: list<Node\Stmt>, description: string, key: string|null} $resolved
     *
     * @return array{checked: bool, certain: bool}
     */
    protected function checkVerdict(array $resolved, Registry $registry, RuleContext $context): array
    {
        $graph = $context->callGraph();
        $key = $resolved['key'];
        $primitives = $this->acceptedChecks($registry);

        if ($graph !== null && $key !== null && $graph->knows($key)) {
            if ($graph->reaches($key, $primitives, self::MAX_DEPTH)) {
                return ['checked' => true, 'certain' => true];
            }

            // Nothing found. Whether that means "there is no check" depends on
            // whether the walk saw everything it needed to.
            if ($graph->walkWasComplete($key, $primitives, self::MAX_DEPTH)) {
                return ['checked' => false, 'certain' => true];
            }

            return ['checked' => $this->looksLikeCheckAnywhere($resolved['stmts']), 'certain' => false];
        }

        // A closure has no key to walk from, so its own statements are all
        // there is. The primitives still apply; the heuristic is the fallback.
        if ($this->callsPrimitive($resolved['stmts'], $primitives)) {
            return ['checked' => true, 'certain' => true];
        }

        return ['checked' => $this->looksLikeCheckAnywhere($resolved['stmts']), 'certain' => false];
    }

    /**
     * @param list<Node\Stmt> $stmts
     * @param list<string>    $primitives
     */
    private function callsPrimitive(array $stmts, array $primitives): bool
    {
        $wanted = array_flip($primitives);

        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name !== null && isset($wanted[strtolower($name)])) {
                return true;
            }
        }

        return false;
    }

    /**
     * The heuristic, kept only for callbacks the graph cannot speak for.
     *
     * @param list<Node\Stmt> $stmts
     */
    private function looksLikeCheckAnywhere(array $stmts): bool
    {
        $finder = new NodeFinder();

        foreach ($finder->findInstanceOf($stmts, Node\Expr\FuncCall::class) as $call) {
            if ($call instanceof Node\Expr\FuncCall) {
                $name = AstHelper::functionName($call);

                if ($name !== null && $this->looksLikeCheck($name)) {
                    return true;
                }
            }
        }

        foreach ([Node\Expr\MethodCall::class, Node\Expr\StaticCall::class] as $class) {
            foreach ($finder->findInstanceOf($stmts, $class) as $call) {
                /** @var Node\Expr\MethodCall|Node\Expr\StaticCall $call */
                if ($call->name instanceof Node\Identifier && $this->looksLikeCheck($call->name->toString())) {
                    return true;
                }
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

        foreach (AstHelper::findAll($file->ast(), Node\Stmt\ClassLike::class) as $classLike) {
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
        bool $imprecise,
    ): Finding {
        $line = $call->getStartLine();
        $column = self::column($call, $file->sourceMap);
        $snippet = trim($file->sourceMap->line($line));

        $reach = $this->reachDescription($hook);

        $step = new TraceStep(
            TraceVerb::Sink,
            $file->relativePath,
            $line,
            $column,
            null,
            $snippet,
            sprintf(
                '%s Nothing reachable from the callback (%s) checks a capability or a nonce.%s',
                $reach,
                $callbackDescription,
                $imprecise
                    ? ' The call graph below it could not be walked completely, so this is a best effort.'
                    : '',
            ),
            TaintSet::of(TaintKind::Authz),
        );

        return new Finding(
            $this->ruleId(),
            $registry->rule($this->ruleId()),
            $this->severityFor($hook),
            TaintKind::Authz,
            $file->relativePath,
            $line,
            $column,
            null,
            $registry->ruleMessage($this->ruleId()),
            [$step],
            Fingerprint::compute($this->ruleId(), $file->relativePath, $hook, $snippet),
            $imprecise,
            $hook,
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
