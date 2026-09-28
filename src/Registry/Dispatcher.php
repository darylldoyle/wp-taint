<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * A function that calls something else on your behalf.
 *
 * `call_user_func( $cb, $x )` is not a call to `call_user_func`; it is a call to
 * whatever `$cb` names, and modelling it as the former loses every flow that
 * passes through it. WordPress routes an enormous amount of control flow this
 * way, so this is the difference between following a plugin's actual behaviour
 * and stopping at the first indirection.
 *
 * Declared as data so a project can teach the engine about its own dispatcher
 * without touching the analyser.
 */
final class Dispatcher
{
    public function __construct(
        public readonly Matcher $matcher,
        /**
         * Which argument names the callee.
         *
         * A callable value, normally. When {@see $hook} is set it is a hook
         * name instead, and the callees come from the hook graph.
         */
        public readonly int $callable,
        public readonly DispatchMode $mode,
        /** Where the callee's arguments start, in the dispatcher's own list. */
        public readonly int $argumentStart,
        public readonly DispatchReturn $returns,
        /**
         * True when the `callable` argument is a hook name rather than a
         * callable. `apply_filters()` and `do_action()` are dispatchers like
         * any other; they just look their callees up somewhere else.
         */
        public readonly bool $hook = false,
        public readonly ?string $note = null,
        /**
         * The separator a hook's modifiers are joined with, when the hook
         * argument may be an array: a name, then modifiers that each fire a
         * longer name as well. Gravity Forms dispatches this way with `_`:
         * `gf_do_action( array( 'gform_after_submission', $form_id ), $entry,
         * $form )` fires `gform_after_submission` and then
         * `gform_after_submission_{$form_id}`. The older form passes the
         * modifier as the second argument instead, and the callee's arguments
         * then start one later. Null for a hook argument that is one name.
         */
        public readonly ?string $modifierSeparator = null,
        /**
         * Where each of the callee's parameters gets its value, when the
         * mode alone does not say: the dispatcher's arguments whose taint it
         * receives, by parameter. `array_walk( $items, $cb, $extra )` calls
         * `$cb( $item, $key, $extra )`, which is `[[0], [0], [2]]`. Null hands
         * the callee the arguments from {@see $argumentStart}, one per
         * parameter.
         *
         * @var list<list<int>>|null
         */
        public readonly ?array $parameters = null,
    ) {
    }
}
