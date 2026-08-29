<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Hooks\HookGraph;
use Enshrined\WpTaint\Taint\CallGraph;
use Enshrined\WpTaint\Taint\DeclaredTypes;
use Enshrined\WpTaint\Taint\TaintSet;

/**
 * Shared state for structural rules across the whole scan.
 *
 * Hook callbacks are frequently registered in one file and defined in another,
 * so the AJAX rule needs a view wider than the file it is looking at.
 *
 * It also carries the call and hook graphs, which is what turned the
 * authorization rules from name matching into a reachability question: "does
 * anything below this callback check a capability" cannot be answered from one
 * file's syntax.
 */
final class RuleContext
{
    /** @var array<string, UnresolvedHook> */
    private array $unresolvedHooks = [];

    /**
     * Findings whose verdict needs a function summary, which does not exist
     * yet when structural rules run.
     *
     * Structural rules walk the AST before the taint pass, and the AST is
     * released as soon as they finish — the two passes cannot swap order and
     * cannot coexist. What a rule *can* do is record the finding it would
     * emit together with the question that decides it, and let the scanner
     * adjudicate once summaries exist.
     *
     * The one question currently asked: does taint of these kinds survive
     * from the callback's first parameter to its return? `register_setting()`
     * with a user-defined `sanitize_callback` is the customer — a callback
     * that hands the posted value back unchanged cleans nothing, and only its
     * summary can say so.
     *
     * @var list<array{finding: Finding, callbackKey: string, survivesKinds: TaintSet}>
     */
    private array $deferred = [];

    /**
     * Emit this finding later, unless the callback's summary clears the kinds.
     */
    public function deferUnlessCallbackClears(Finding $finding, string $callbackKey, TaintSet $kinds): void
    {
        $this->deferred[] = [
            'finding' => $finding,
            'callbackKey' => strtolower(ltrim($callbackKey, '\\')),
            'survivesKinds' => $kinds,
        ];
    }

    /**
     * @return list<array{finding: Finding, callbackKey: string, survivesKinds: TaintSet}>
     */
    public function deferredFindings(): array
    {
        return $this->deferred;
    }

    private ?CallGraph $callGraph = null;

    private ?HookGraph $hookGraph = null;

    /**
     * What the whole scan declares about its own types, for the rules whose
     * one-file AST cannot answer a cross-file question. The loader pattern is
     * the customer: the component class and the registration that names it are
     * regularly in different files.
     */
    private ?DeclaredTypes $declaredTypes = null;

    public function withDeclaredTypes(DeclaredTypes $types): self
    {
        $context = clone $this;
        $context->declaredTypes = $types;

        return $context;
    }

    public function declaredTypes(): ?DeclaredTypes
    {
        return $this->declaredTypes;
    }

    /**
     * The graphs are built after this object, because they need every file
     * parsed first. Returns a new context rather than mutating, so nothing can
     * observe it half-built.
     */
    public function withGraphs(CallGraph $callGraph, HookGraph $hookGraph): self
    {
        $context = clone $this;
        $context->callGraph = $callGraph;
        $context->hookGraph = $hookGraph;

        return $context;
    }

    public function callGraph(): ?CallGraph
    {
        return $this->callGraph;
    }

    public function hookGraph(): ?HookGraph
    {
        return $this->hookGraph;
    }

    /**
     * Record a hook whose callback could not be resolved.
     *
     * Counted and reported rather than ignored, so that the gap in coverage is
     * visible instead of being mistaken for a clean result.
     */
    public function recordUnresolvedHook(string $hook, string $file, int $line, string $reason): void
    {
        $this->unresolvedHooks[$file . ':' . $line . ':' . $hook] = new UnresolvedHook($hook, $file, $line, $reason);
    }

    /**
     * @return list<UnresolvedHook>
     */
    public function unresolvedHooks(): array
    {
        $hooks = array_values($this->unresolvedHooks);
        usort(
            $hooks,
            static fn (UnresolvedHook $a, UnresolvedHook $b): int => [$a->file, $a->line, $a->hook]
                <=> [$b->file, $b->line, $b->hook],
        );

        return $hooks;
    }
}
