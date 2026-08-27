<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

use Enshrined\WpTaint\Hooks\HookGraph;
use Enshrined\WpTaint\Taint\CallGraph;

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

    private ?CallGraph $callGraph = null;

    private ?HookGraph $hookGraph = null;

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
