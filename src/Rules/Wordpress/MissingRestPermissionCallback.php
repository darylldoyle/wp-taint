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
use Enshrined\WpTaint\Rules\ArrayLiteralResolver;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\HookCallbackResolver;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * `register_rest_route()` with no `permission_callback`, or with
 * `__return_true` on a route that writes.
 *
 * WordPress treats a route without a permission callback as public and has
 * emitted a `_doing_it_wrong()` notice for it since 5.5. `__return_true` on a
 * read-only route is a deliberate choice for public data and is not reported;
 * on POST, PUT, PATCH or DELETE it is an authorization bypass.
 *
 * Three distinct problems, not one:
 *
 * | Reported | Severity | Why |
 * | --- | --- | --- |
 * | No `permission_callback` | high | The route is public and WordPress says so |
 * | `__return_true` on a write | critical | An unauthenticated write |
 * | A callback that decides nothing | medium | It resolves, reaches no capability check, and makes no decision |
 *
 * The third is the new one and it is deliberately the quietest. Two conditions,
 * not one: nothing below the callback reaches an authorization primitive, *and*
 * the callback body contains no branch and no comparison — so it cannot be
 * deciding anything.
 *
 * Both are needed. Akismet's REST permission callback compares a request
 * parameter against the site's API key, which is a real check written with a
 * shared secret rather than a WordPress primitive. Reachability alone reported
 * it; asking whether the body makes a decision does not.
 */
final class MissingRestPermissionCallback implements StructuralRule
{
    private const MISSING_RULE = 'wp.authz.rest-missing-permission-callback';

    private const PUBLIC_WRITE_RULE = 'wp.authz.rest-public-write';

    private const NO_CHECK_RULE = 'wp.authz.rest-permission-callback-no-check';

    /** @see MissingAjaxCapabilityCheck::MAX_DEPTH */
    private const MAX_DEPTH = 6;

    private const WRITE_METHODS = ['post', 'put', 'patch', 'delete', 'editable', 'creatable', 'deletable'];

    public function id(): string
    {
        return self::MISSING_RULE;
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

            if (AstHelper::functionName($call) !== 'register_rest_route') {
                continue;
            }

            $finding = $this->inspect($call, $file, $registry, $context);

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    private function inspect(
        Node\Expr\FuncCall $call,
        ParsedFile $file,
        Registry $registry,
        RuleContext $context,
    ): ?Finding {
        $argument = AstHelper::argument($call, 2);
        $options = $argument === null
            ? null
            : (new ArrayLiteralResolver($file->ast()))->resolve($argument, $this->enclosingFunction($file, $call));

        if ($options === null) {
            // Options built conditionally, appended to, or handed in from
            // somewhere this cannot fold. Reporting would be a guess; counting
            // keeps the gap visible.
            $context->recordUnresolvedHook(
                'register_rest_route',
                $file->relativePath,
                $call->getStartLine(),
                'route options could not be resolved to an array literal',
            );

            return null;
        }

        // register_rest_route() also accepts a list of route definitions.
        $definitions = $this->routeDefinitions($options);

        foreach ($definitions as $definition) {
            $finding = $this->inspectDefinition($call, $definition, $file, $registry, $context);

            if ($finding !== null) {
                return $finding;
            }
        }

        return null;
    }

    /**
     * `register_rest_route()` takes either one route definition or a list of
     * them, and the list form can carry a shared `args` entry alongside.
     *
     * ```php
     * register_rest_route( 'ns/v1', '/thing', [
     *     'args' => [ 'id' => [ 'type' => 'integer' ] ],   // shared, string key
     *     [ 'methods' => 'GET',  'permission_callback' => '…', 'callback' => '…' ],
     *     [ 'methods' => 'POST', 'permission_callback' => '…', 'callback' => '…' ],
     * ] );
     * ```
     *
     * Only the integer-keyed entries are route definitions. Treating `args` as
     * one produced a false positive on Akismet, because a schema block has no
     * `permission_callback` and never should.
     *
     * @return list<Node\Expr\Array_>
     */
    private function routeDefinitions(Node\Expr\Array_ $options): array
    {
        if (AstHelper::hasArrayKey($options, 'methods') || AstHelper::hasArrayKey($options, 'callback')) {
            return [$options];
        }

        $definitions = [];

        foreach ($options->items as $item) {
            if ($item === null || $item->key !== null) {
                continue;
            }

            if ($item->value instanceof Node\Expr\Array_) {
                $definitions[] = $item->value;
            }
        }

        return $definitions === [] ? [$options] : $definitions;
    }

    private function inspectDefinition(
        Node\Expr\FuncCall $call,
        Node\Expr\Array_ $definition,
        ParsedFile $file,
        Registry $registry,
        RuleContext $context,
    ): ?Finding {
        if (AstHelper::hasDynamicKeys($definition)) {
            $context->recordUnresolvedHook(
                'register_rest_route',
                $file->relativePath,
                $call->getStartLine(),
                'route options contain dynamic or spread keys',
            );

            return null;
        }

        $permission = AstHelper::arrayItem($definition, 'permission_callback');

        if ($permission === null) {
            return $this->finding(
                self::MISSING_RULE,
                Severity::High,
                $call,
                $file,
                $registry,
                'register_rest_route() declares no permission_callback, so the route is public.',
            );
        }

        if ($this->isReturnTrue($permission)) {
            if (! $this->hasWriteMethod($definition)) {
                return null;
            }

            return $this->finding(
                self::PUBLIC_WRITE_RULE,
                Severity::Critical,
                $call,
                $file,
                $registry,
                "permission_callback is '__return_true' on a route that writes, so any unauthenticated request can "
                    . 'invoke it.',
            );
        }

        return $this->inspectCallbackBody($call, $permission, $file, $registry, $context);
    }

    /**
     * A `permission_callback` that is present but decides nothing.
     *
     * Presence used to be the whole test, which credited
     * `'permission_callback' => array( $this, 'noop' )` exactly as much as a
     * real capability check.
     *
     * Silent unless three things hold: the callback resolves, the walk below it
     * was complete, and its body makes no decision. Quiet by design — the cost
     * of being wrong on an authorization rule is the tool being muted, and this
     * is the one class of the three that can be wrong.
     */
    private function inspectCallbackBody(
        Node\Expr\FuncCall $call,
        Node\Expr $permission,
        ParsedFile $file,
        Registry $registry,
        RuleContext $context,
    ): ?Finding {
        $graph = $context->callGraph();

        if ($graph === null) {
            return null;
        }

        $resolved = (new HookCallbackResolver($file->ast()))
            ->resolve($permission, $this->enclosingClass($file, $call));

        if ($resolved === null || $resolved['key'] === null || ! $graph->knows($resolved['key'])) {
            return null;
        }

        $primitives = $registry->authorizationChecks();

        if ($graph->reaches($resolved['key'], $primitives, self::MAX_DEPTH)) {
            return null;
        }

        if (! $graph->walkWasComplete($resolved['key'], $primitives, self::MAX_DEPTH)) {
            return null;
        }

        if (! $this->makesNoDecision($resolved['stmts'])) {
            return null;
        }

        return $this->finding(
            self::NO_CHECK_RULE,
            Severity::Medium,
            $call,
            $file,
            $registry,
            sprintf(
                'permission_callback is %s. It reaches no capability or nonce check, and its body contains no '
                    . 'branch or comparison, so it cannot be refusing anything.',
                $resolved['description'],
            ),
        );
    }

    /**
     * Whether a body could be making a decision at all.
     *
     * A cheap syntactic proxy for "provably returns a constant", and named as
     * one: any branch, comparison, boolean operator or negation counts as a
     * decision, whether or not it is really an authorization one. Being wrong
     * here means staying quiet, which is the direction this rule should fail in.
     *
     * @param list<Node\Stmt> $stmts
     */
    private function makesNoDecision(array $stmts): bool
    {
        $deciding = [
            Node\Stmt\If_::class,
            Node\Stmt\Switch_::class,
            Node\Expr\Ternary::class,
            Node\Expr\Match_::class,
            Node\Expr\BinaryOp::class,
            Node\Expr\BooleanNot::class,
            Node\Expr\Empty_::class,
            Node\Expr\Isset_::class,
        ];

        $finder = new NodeFinder();

        foreach ($deciding as $class) {
            if ($finder->findFirstInstanceOf($stmts, $class) !== null) {
                return false;
            }
        }

        return true;
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

    /**
     * The function or method the call sits inside, so a variable lookup does
     * not wander into an unrelated scope.
     */
    private function enclosingFunction(ParsedFile $file, Node $node): ?Node\FunctionLike
    {
        $line = $node->getStartLine();
        $best = null;

        foreach (AstHelper::findAll($file->ast(), Node\FunctionLike::class) as $function) {
            if (! $function instanceof Node\FunctionLike) {
                continue;
            }

            if ($function->getStartLine() > $line || $line > $function->getEndLine()) {
                continue;
            }

            // Innermost wins: a closure inside a method is its own scope.
            if ($best === null || $function->getStartLine() > $best->getStartLine()) {
                $best = $function;
            }
        }

        return $best;
    }

    private function isReturnTrue(Node\Expr $permission): bool
    {
        $value = AstHelper::stringValue($permission);

        if ($value !== null) {
            return strtolower(ltrim($value, '\\')) === '__return_true';
        }

        // `'permission_callback' => fn () => true` and
        // `function () { return true; }` are the same bypass written longhand.
        if ($permission instanceof Node\Expr\ArrowFunction) {
            return $permission->expr instanceof Node\Expr\ConstFetch
                && strtolower($permission->expr->name->toString()) === 'true';
        }

        if ($permission instanceof Node\Expr\Closure) {
            $statements = array_values($permission->stmts);

            if (count($statements) !== 1) {
                return false;
            }

            $only = $statements[0];

            return $only instanceof Node\Stmt\Return_
                && $only->expr instanceof Node\Expr\ConstFetch
                && strtolower($only->expr->name->toString()) === 'true';
        }

        return false;
    }

    private function hasWriteMethod(Node\Expr\Array_ $definition): bool
    {
        $methods = AstHelper::arrayItem($definition, 'methods');

        if ($methods === null) {
            // No `methods` key means WP_REST_Server::ALLMETHODS, which includes
            // every write verb.
            return true;
        }

        foreach ($this->methodNames($methods) as $method) {
            if (in_array($method, self::WRITE_METHODS, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function methodNames(Node\Expr $methods): array
    {
        if ($methods instanceof Node\Expr\Array_) {
            $names = [];

            foreach ($methods->items as $item) {
                if ($item !== null) {
                    $names = [...$names, ...$this->methodNames($item->value)];
                }
            }

            return $names;
        }

        $literal = AstHelper::stringValue($methods);

        if ($literal !== null) {
            // 'POST, PUT' is a legal value.
            return array_values(array_filter(
                array_map(static fn (string $part): string => strtolower(trim($part)), explode(',', $literal)),
                static fn (string $part): bool => $part !== '',
            ));
        }

        if ($methods instanceof Node\Expr\ClassConstFetch && $methods->name instanceof Node\Identifier) {
            // WP_REST_Server::EDITABLE, ::CREATABLE, ::DELETABLE, ::ALLMETHODS.
            $constant = strtolower($methods->name->toString());

            return $constant === 'allmethods' ? self::WRITE_METHODS : [$constant];
        }

        // An expression we cannot read. Assume it may include a write verb:
        // under-reporting an authorization bypass is worse than the alternative
        // here, and the shape is rare.
        return ['post'];
    }

    private function finding(
        string $ruleId,
        Severity $severity,
        Node\Expr\FuncCall $call,
        ParsedFile $file,
        Registry $registry,
        string $description,
    ): Finding {
        $line = $call->getStartLine();
        $column = self::column($call, $file->sourceMap);
        $snippet = trim($file->sourceMap->line($line));

        $step = new TraceStep(
            TraceVerb::Sink,
            $file->relativePath,
            $line,
            $column,
            null,
            $snippet,
            $description,
            TaintSet::of(TaintKind::Authz),
        );

        return new Finding(
            $ruleId,
            $registry->rule($ruleId),
            $severity,
            TaintKind::Authz,
            $file->relativePath,
            $line,
            $column,
            null,
            $registry->ruleMessage($ruleId),
            [$step],
            Fingerprint::compute($ruleId, $file->relativePath, 'register_rest_route', $snippet),
            false,
            'register_rest_route()',
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
