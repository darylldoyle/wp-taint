<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

use Enshrined\WpTaint\Taint\DynamicCallPolicy;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\Console\Input\InputInterface;

/**
 * Typed reads of Symfony Console input.
 *
 * `getOption()` and `getArgument()` both return `mixed`, so every option read
 * would otherwise be an unchecked cast. Funnelling them through here keeps the
 * commands honest under PHPStan and turns a misconfigured option into a clear
 * error rather than a silent `(string) null`.
 */
final class InputReader
{
    public function __construct(private readonly InputInterface $input)
    {
    }

    public function string(string $name, string $default = ''): string
    {
        $value = $this->input->getOption($name);

        if (is_string($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return $default;
    }

    public function nullableString(string $name): ?string
    {
        $value = $this->string($name);

        return $value === '' ? null : $value;
    }

    public function bool(string $name): bool
    {
        return $this->input->getOption($name) === true;
    }

    public function int(string $name, int $default): int
    {
        $value = $this->input->getOption($name);

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        return $default;
    }

    /**
     * @return list<string>
     */
    public function stringList(string $name): array
    {
        $value = $this->input->getOption($name);

        if (! is_array($value)) {
            return [];
        }

        $result = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $result[] = $item;
            }
        }

        return $result;
    }

    /**
     * @return list<string>
     */
    public function stringArgumentList(string $name): array
    {
        $value = $this->input->getArgument($name);

        if (! is_array($value)) {
            return [];
        }

        $result = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $result[] = $item;
            }
        }

        return $result;
    }

    public function stringArgument(string $name): string
    {
        $value = $this->input->getArgument($name);

        if (! is_string($value)) {
            throw new RuntimeException(sprintf('The %s argument is required.', $name));
        }

        return $value;
    }

    /**
     * `--generate-baseline` is `VALUE_OPTIONAL` with a `false` default, so it
     * has three states: absent, present with no value, and present with a
     * value.
     */
    /**
     * `--dynamic-calls`, honouring the flag it replaced.
     *
     * `--assume-dynamic-tainted` was the only setting before there were three,
     * and scripts in CI still pass it. It maps onto `tainted`; an explicit
     * `--dynamic-calls` wins if both are given.
     */
    public function dynamicCallPolicy(): DynamicCallPolicy
    {
        $value = $this->nullableString('dynamic-calls');

        if ($value === null) {
            return $this->bool('assume-dynamic-tainted')
                ? DynamicCallPolicy::Tainted
                : DynamicCallPolicy::Propagate;
        }

        $policy = DynamicCallPolicy::tryFrom(strtolower($value));

        if ($policy === null) {
            throw new InvalidArgumentException(sprintf(
                '--dynamic-calls must be one of %s, got "%s".',
                implode(', ', array_map(
                    static fn (DynamicCallPolicy $p): string => $p->value,
                    DynamicCallPolicy::cases(),
                )),
                $value,
            ));
        }

        return $policy;
    }

    public function optionalValue(string $name, string $whenPresentWithoutValue): ?string
    {
        $value = $this->input->getOption($name);

        if ($value === false) {
            return null;
        }

        if ($value === null || $value === '') {
            return $whenPresentWithoutValue;
        }

        return is_string($value) ? $value : $whenPresentWithoutValue;
    }
}
