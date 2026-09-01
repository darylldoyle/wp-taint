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

    /**
     * Registrations whose hook name folds only to a literal head —
     * `add_action( "save_{$type}", $cb )` — keyed by that prefix.
     *
     * @var array<string, list<HookRegistration>>
     */
    private array $byPrefix = [];

    /**
     * A prefix shorter than this joins nothing: `wp_` would connect a dynamic
     * name to half of core's hook namespace, and a join that wide is a guess
     * wearing a prefix's clothes.
     */
    public const MIN_PREFIX = 4;

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
     * A registration whose hook name folded only to its literal head.
     *
     * The registration's `hook` field holds the prefix. Too short a prefix is
     * refused and the caller should fall back to treating the registration as
     * unplaced.
     */
    public function addPrefix(HookRegistration $registration): bool
    {
        if (strlen($registration->hook) < self::MIN_PREFIX) {
            return false;
        }

        $identity = 'prefix:' . $registration->sortKey();

        if (isset($this->seen[$identity])) {
            return true;
        }

        $this->seen[$identity] = true;
        $this->byPrefix[$registration->hook][] = $registration;

        return true;
    }

    /**
     * Every callback registered on a hook.
     *
     * A literal dispatch also reaches the dynamic registrations whose prefix
     * it starts with: `do_action( 'save_post' )` runs whatever
     * `add_action( "save_{$type}", $cb )` registered, for the `$type` values
     * the scan could not fold.
     *
     * @return list<HookRegistration>
     */
    public function callbacksFor(string $hook): array
    {
        $registrations = $this->byHook[$hook] ?? [];

        foreach ($this->byPrefix as $prefix => $prefixed) {
            if (str_starts_with($hook, $prefix)) {
                $registrations = [...$registrations, ...$prefixed];
            }
        }

        usort(
            $registrations,
            static fn (HookRegistration $a, HookRegistration $b): int => $a->sortKey() <=> $b->sortKey(),
        );

        return $registrations;
    }

    /**
     * Every callback a dynamically-named dispatch could reach, by its folded
     * head: `do_action( "save_{$type}" )` runs whatever is registered on any
     * literal hook starting with `save_`, and whatever dynamic registration
     * shares a compatible prefix.
     *
     * @return list<CallTarget>
     */
    public function targetsMatchingPrefix(string $needle): array
    {
        if (strlen($needle) < self::MIN_PREFIX) {
            return [];
        }

        $matched = [];

        foreach ($this->byHook as $hook => $registrations) {
            // Synthetic entries — shortcode and block callbacks — are not
            // hooks a do_action() can reach.
            if (str_starts_with($hook, HookGraphBuilder::SHORTCODE_PREFIX)) {
                continue;
            }

            if (str_starts_with($hook, $needle)) {
                $matched = [...$matched, ...$registrations];
            }
        }

        // Two dynamic names whose known heads are compatible — one extends
        // the other — can be the same hook at runtime.
        foreach ($this->byPrefix as $prefix => $registrations) {
            if (str_starts_with($prefix, $needle) || str_starts_with($needle, $prefix)) {
                $matched = [...$matched, ...$registrations];
            }
        }

        usort(
            $matched,
            static fn (HookRegistration $a, HookRegistration $b): int => $a->sortKey() <=> $b->sortKey(),
        );

        return array_map(static fn (HookRegistration $r): CallTarget => $r->callback, $matched);
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
     * Callbacks whose return value WordPress prints, and what each one is.
     *
     * A shortcode handler and a dynamic block's `render_callback` need exactly
     * the same thing from the analysis: there is no `echo` in the plugin to
     * find, because core does the printing. They are told apart only so the
     * finding can name the right one.
     *
     * A shortcode's attributes come from post content and are seeded; a block's
     * are not, because a block's inner content is already-rendered markup that
     * is meant to be printed as it is.
     *
     * @return array<string, string> function key => 'shortcode callback' or
     *                               'block render callback'
     */
    public function printedReturnCallbacks(): array
    {
        $keys = [];

        foreach ($this->byHook as $hook => $registrations) {
            $label = match (true) {
                str_starts_with($hook, HookGraphBuilder::SHORTCODE_PREFIX) => 'shortcode callback',
                str_starts_with($hook, HookGraphBuilder::BLOCK_PREFIX) => 'block render callback',
                default => null,
            };

            if ($label === null) {
                continue;
            }

            foreach ($registrations as $registration) {
                $key = $registration->callback->userFunctionKey;

                if ($key !== null) {
                    $keys[$key] = $label;
                }
            }
        }

        return $keys;
    }

    /**
     * Just the shortcode handlers, whose parameters carry post content.
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
