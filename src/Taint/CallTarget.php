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
    public static function dynamic(array $arguments, string $displayName): self
    {
        return new self($arguments, null, null, $displayName, true);
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
        );
    }
}
