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
    ) {
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
}
