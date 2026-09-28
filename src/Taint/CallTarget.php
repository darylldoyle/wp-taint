<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Registry\Matcher;
use PHPCfg\Operand;

/**
 * What a call op resolved to.
 *
 * `matcher` is set when the callee has a static name we can look up in the
 * registry. `userFunctionKey` is set when it names a function in the scanned
 * code. Both can be set: a plugin may define a function that the registry also
 * models, and the registry wins.
 *
 * When neither is set the call is dynamic and the analysis is imprecise there.
 *
 * One call op can produce several of these. `call_user_func( $cb, $x )` where
 * `$cb` holds one of two names on either side of a branch reaches both, and
 * choosing one would be a guess; the analysis unions their effects instead.
 */
final class CallTarget
{
    /**
     * @param list<Operand> $arguments
     */
    private function __construct(
        public readonly array $arguments,
        public readonly ?Matcher $matcher,
        public readonly ?string $userFunctionKey,
        public readonly ?string $displayName,
        public readonly bool $dynamic,
        public readonly CallResultMode $resultMode = CallResultMode::Value,
        /**
         * For a dynamic target: the functions in the scan it could be, as far
         * as the scan can say. A named method on an untyped receiver is one of
         * the methods of that name; a computed name on a receiver whose class
         * is known is one of that class's methods. Empty when nothing about the
         * callee can be seen.
         *
         * @var list<string>
         */
        public readonly array $candidates = [],
        /**
         * For a dynamic target: a dispatcher runs it, and dispatchers such as
         * `call_user_func()` and `array_map()` pass their arguments by value,
         * so the callee cannot write back through them whatever it is.
         */
        public readonly bool $passesByValue = false,
        /**
         * A hook dispatch runs this callback; nothing calls it by name.
         *
         * The scan cannot know which callbacks are on a hook when it fires. A
         * registration can sit behind a condition, `remove_filter()` can take
         * it off, and code outside the scan can add or remove callbacks. So
         * the callback may run, which is enough to follow its dataflow, but
         * it is not something the caller does.
         */
        public readonly bool $viaHook = false,
        /**
         * Each argument is the value the callee's parameter at its position
         * receives. Not so when a dispatcher hands the callee the elements of
         * an array, `call_user_func_array()` or `array_map()`, nor for a call
         * written with `...$args`: see {@see ArgumentLayout}.
         */
        public readonly bool $positional = true,
        /**
         * Further values a parameter receives besides its argument, by
         * parameter position. `array_reduce()` hands its callback's `$carry`
         * the initial value and, after the first call, what the callback
         * returned, which is built from the items.
         *
         * @var array<int, list<Operand>>
         */
        public readonly array $moreArguments = [],
        /**
         * Each argument stands for the items of an array, and never for its
         * keys. `array_map( $cb, $items )` hands `$cb` one value at a time, and
         * `call_user_func_array( $cb, $args )` hands it the values of `$args`,
         * so a key that carries taint reaches neither. See
         * {@see \Enshrined\WpTaint\Registry\Dispatcher::$valuesOnly}.
         */
        public readonly bool $itemsOnly = false,
    ) {
    }

    /**
     * The same callee, with its return value going somewhere else.
     *
     * Only a dispatcher sets this: it knows whether it hands its callee's
     * return back, collects it into an array, or discards it.
     */
    public function returningTo(CallResultMode $mode): self
    {
        return new self(
            $this->arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $mode,
            $this->candidates,
            $this->passesByValue,
            $this->viaHook,
            $this->positional,
            $this->moreArguments,
            $this->itemsOnly,
        );
    }

    /**
     * The same callee, run by a hook dispatch. See {@see $viaHook}.
     */
    public function runByHook(): self
    {
        return new self(
            $this->arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $this->resultMode,
            $this->candidates,
            $this->passesByValue,
            true,
            $this->positional,
            $this->moreArguments,
            $this->itemsOnly,
        );
    }

    /**
     * @param list<Operand> $arguments
     */
    public static function resolved(
        array $arguments,
        ?Matcher $matcher,
        ?string $userFunctionKey,
        string $displayName,
    ): self {
        return new self($arguments, $matcher, $userFunctionKey, $displayName, false);
    }

    /**
     * @param list<Operand> $arguments
     */
    /**
     * @param list<Operand> $arguments
     * @param list<string>  $candidates see {@see $candidates}
     */
    public static function dynamic(array $arguments, string $displayName, array $candidates = []): self
    {
        return new self($arguments, null, null, $displayName, true, CallResultMode::Value, $candidates);
    }

    /**
     * A callable a dispatcher runs that could not be pinned down.
     *
     * @param list<Operand> $arguments
     */
    public static function dynamicDispatch(array $arguments, string $displayName): self
    {
        return new self($arguments, null, null, $displayName, true, CallResultMode::Value, [], true);
    }

    public function isResolved(): bool
    {
        return $this->matcher !== null || $this->userFunctionKey !== null;
    }

    public function argument(int $index): ?Operand
    {
        return $this->arguments[$index] ?? null;
    }

    public function argumentCount(): int
    {
        return count($this->arguments);
    }

    public function name(): string
    {
        return $this->displayName ?? 'unknown';
    }

    /**
     * The same callee reached twice through different syntax.
     *
     * Two branches assigning the same callback name produce two identical
     * targets, and analysing both would double every finding on that line.
     */
    public function identity(): string
    {
        return implode('|', [
            $this->dynamic ? 'dynamic' : 'resolved',
            $this->matcher?->identity() ?? '',
            $this->userFunctionKey ?? '',
            $this->displayName ?? '',
        ]);
    }

    /**
     * The same callee, called with different arguments.
     *
     * A dispatcher resolves the callee from one argument and passes the rest
     * along, so the target is built before its real arguments are known.
     *
     * @param list<Operand> $arguments
     */
    public function withArguments(array $arguments): self
    {
        return new self(
            $arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $this->resultMode,
            $this->candidates,
            $this->passesByValue,
            $this->viaHook,
            $this->positional,
            $this->moreArguments,
            $this->itemsOnly,
        );
    }

    /**
     * The same callee, with its arguments laid out by the callee's parameters.
     *
     * @param list<Operand>              $arguments one per parameter position
     * @param array<int, list<Operand>> $more      see {@see $moreArguments}
     */
    public function withParameterArguments(array $arguments, array $more, bool $positional): self
    {
        return new self(
            $arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $this->resultMode,
            $this->candidates,
            $this->passesByValue,
            $this->viaHook,
            $positional && $this->positional,
            $more,
        );
    }

    /**
     * The same callee, with arguments that are not each a parameter's value.
     * See {@see $positional}.
     */
    public function notPositional(): self
    {
        return new self(
            $this->arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $this->resultMode,
            $this->candidates,
            $this->passesByValue,
            $this->viaHook,
            false,
            $this->moreArguments,
            $this->itemsOnly,
        );
    }

    /**
     * The same callee, handed the items of each argument rather than the
     * array. See {@see $itemsOnly}.
     */
    public function itemsOnly(): self
    {
        return new self(
            $this->arguments,
            $this->matcher,
            $this->userFunctionKey,
            $this->displayName,
            $this->dynamic,
            $this->resultMode,
            $this->candidates,
            $this->passesByValue,
            $this->viaHook,
            $this->positional,
            $this->moreArguments,
            true,
        );
    }
}
