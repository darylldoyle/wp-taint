<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use InvalidArgumentException;

/**
 * What a registry entry matches against in the CFG.
 *
 * `key()` is also the override key: a later registry redefining
 * `function:esc_url` replaces the earlier one wholesale rather than merging
 * with it, because a half-merged escaper definition is worse than either.
 */
final class Matcher
{
    private function __construct(
        public readonly MatcherKind $kind,
        public readonly string $name,
        public readonly ?string $class = null,
    ) {
    }

    public static function superglobal(string $name): self
    {
        return new self(MatcherKind::Superglobal, ltrim($name, '$'));
    }

    public static function function(string $name): self
    {
        return new self(MatcherKind::Func, self::normaliseFunctionName($name));
    }

    public static function method(string $class, string $method): self
    {
        return new self(MatcherKind::Method, strtolower($method), ltrim(strtolower($class), '\\'));
    }

    public static function staticMethod(string $class, string $method): self
    {
        return new self(MatcherKind::StaticMethod, strtolower($method), ltrim(strtolower($class), '\\'));
    }

    public static function construct(string $name): self
    {
        $name = strtolower($name);

        if (! in_array($name, self::supportedConstructs(), true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown construct "%s". Supported constructs: %s.',
                $name,
                implode(', ', self::supportedConstructs()),
            ));
        }

        return new self(MatcherKind::Construct, $name);
    }

    /**
     * @return list<string>
     */
    public static function supportedConstructs(): array
    {
        // No `backtick`: php-cfg lowers `` `cmd` `` to a shell_exec() call, so
        // the existing function sink already covers it.
        return ['echo', 'print', 'eval', 'include', 'include_once', 'require', 'require_once'];
    }

    public function key(): string
    {
        return match ($this->kind) {
            MatcherKind::Superglobal => 'superglobal:' . $this->name,
            MatcherKind::Func => 'function:' . $this->name,
            MatcherKind::Method => 'method:' . $this->class . '::' . $this->name,
            MatcherKind::StaticMethod => 'static_method:' . $this->class . '::' . $this->name,
            MatcherKind::Construct => 'construct:' . $this->name,
        };
    }

    /**
     * How the entry is written in output: `esc_html()`, `wpdb::query()`, `echo`.
     */
    public function describe(): string
    {
        return match ($this->kind) {
            MatcherKind::Superglobal => '$' . $this->name,
            MatcherKind::Func => $this->name . '()',
            MatcherKind::Method, MatcherKind::StaticMethod => $this->class . '::' . $this->name . '()',
            MatcherKind::Construct => $this->name,
        };
    }

    /**
     * Bare identity for fingerprinting: no parentheses, no sigil.
     */
    public function identity(): string
    {
        return match ($this->kind) {
            MatcherKind::Superglobal => '$' . $this->name,
            MatcherKind::Func, MatcherKind::Construct => $this->name,
            MatcherKind::Method, MatcherKind::StaticMethod => $this->class . '::' . $this->name,
        };
    }

    /**
     * Function names are matched case-insensitively without a leading
     * separator, because PHP resolves them that way and WordPress code is
     * inconsistent about both.
     */
    private static function normaliseFunctionName(string $name): string
    {
        return strtolower(ltrim($name, '\\'));
    }
}
