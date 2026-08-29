<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\CallTarget;

/**
 * Which callbacks run on which hook.
 *
 * The corpus holds 15,637 `add_action`/`add_filter` registrations and 9,173
 * `apply_filters` calls. Until this existed, every one of those was a hole: a
 * filter callback reading `$_GET` could taint a value the engine believed was
 * clean, and an action's arguments never reached the sinks inside its
 * callbacks.
 *
 * Once the graph exists, a hook dispatch is just a call with several callees,
 * which the analysis already knows how to do — the same machinery that resolves
 * `call_user_func()`. Priority does not change a union, so it is recorded for
 * the trace text and otherwise ignored.
 *
 * ## What a missing hook name means
 *
 * A registration whose hook name will not resolve is kept, separately, and
 * surfaced in the unresolved-hook list — because "we saw a registration we could
 * not place" and "there are no callbacks on this hook" are very different
 * answers, and the second must never be reported when the first is true.
 *
 * It is deliberately *not* unioned into every dispatch. That would be the sound
 * choice and it is the wrong one here: Advanced Custom Fields has 22 such
 * registrations against 201 hooks, so every dispatch would gain 22 spurious
 * callees — a large precision loss and an N×M cost, to model an edge that
 * probably is not there. The tool's standing trade applies: a documented false
 * negative beats an undocumented false positive.
 */
final class HookGraph
{
    /**
     * Registrations whose hook name resolved, keyed by hook name.
     *
     * @var array<string, list<HookRegistration>>
     */
    private array $byHook = [];

    /**
     * Registrations whose hook name did not resolve.
     *
     * @var list<HookRegistration>
     */
    private array $unplaced = [];

    /** @var array<string, true> */
    private array $seen = [];

    public function add(HookRegistration $registration): void
    {
        // The same registration can be reached more than once: a file included
        // from two places, or a worker re-analysing a function in a later
        // round. Deduplicated by position, so the graph is a set.
        $identity = $registration->sortKey();

        if (isset($this->seen[$identity])) {
            return;
        }

        $this->seen[$identity] = true;

        if ($registration->hook === '') {
            $this->unplaced[] = $registration;

            return;
        }

        $this->byHook[$registration->hook][] = $registration;
    }

    /**
     * Every callback registered on a hook.
     *
     * @return list<HookRegistration>
     */
    public function callbacksFor(string $hook): array
    {
        $registrations = $this->byHook[$hook] ?? [];

        usort(
            $registrations,
            static fn (HookRegistration $a, HookRegistration $b): int => $a->sortKey() <=> $b->sortKey(),
        );

        return $registrations;
    }

    /**
     * @return list<CallTarget>
     */
    public function targetsFor(string $hook): array
    {
        return array_map(
            static fn (HookRegistration $r): CallTarget => $r->callback,
            $this->callbacksFor($hook),
        );
    }

    /**
     * Function keys registered as shortcode callbacks.
     *
     * WordPress calls these with attributes taken from post content and prints
     * whatever they return, so both ends need modelling: the parameters are
     * attacker-influenced and the return value is output.
     *
     * @return array<string, true>
     */
    public function shortcodeCallbackKeys(): array
    {
        $keys = [];

        foreach ($this->byHook as $hook => $registrations) {
            if (! str_starts_with($hook, HookGraphBuilder::SHORTCODE_PREFIX)) {
                continue;
            }

            foreach ($registrations as $registration) {
                $key = $registration->callback->userFunctionKey;

                if ($key !== null) {
                    $keys[$key] = true;
                }
            }
        }

        return $keys;
    }

    /**
     * Registrations whose hook name could not be resolved.
     *
     * Surfaced rather than modelled. Each one is a place the engine knows it
     * cannot see a hook edge that exists.
     *
     * @return list<HookRegistration>
     */
    public function unplaced(): array
    {
        $unplaced = $this->unplaced;

        usort(
            $unplaced,
            static fn (HookRegistration $a, HookRegistration $b): int => $a->sortKey() <=> $b->sortKey(),
        );

        return $unplaced;
    }

    public function hasUnplaced(): bool
    {
        return $this->unplaced !== [];
    }

    public function isKnown(string $hook): bool
    {
        return isset($this->byHook[$hook]);
    }

    /**
     * @return list<string>
     */
    public function hooks(): array
    {
        $hooks = array_keys($this->byHook);
        sort($hooks);

        return $hooks;
    }

    public function registrationCount(): int
    {
        return count($this->seen);
    }
}
