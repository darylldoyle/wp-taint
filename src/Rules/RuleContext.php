<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules;

/**
 * Shared state for structural rules across the whole scan.
 *
 * Hook callbacks are frequently registered in one file and defined in another,
 * so the AJAX rule needs a view wider than the file it is looking at.
 */
final class RuleContext
{
    /** @var array<string, UnresolvedHook> */
    private array $unresolvedHooks = [];

    /** @var array<string, true> */
    private array $resolvedCleanSites = [];

    /**
     * Tell the shape rules that the dataflow engine understood this sink
     * completely and found it clean, so they should stay quiet about it.
     *
     * @param list<string> $sites `relative/path.php:line`
     */
    public function markOriginsResolved(array $sites): void
    {
        foreach ($sites as $site) {
            $this->resolvedCleanSites[$site] = true;
        }
    }

    public function originsAreResolved(string $file, int $line): bool
    {
        return isset($this->resolvedCleanSites[$file . ':' . $line]);
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
