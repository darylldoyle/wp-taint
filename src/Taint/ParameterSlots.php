<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Operand;

/**
 * One call's arguments, placed on its callee's parameters as PHP places them.
 * See {@see ArgumentLayout}.
 */
final class ParameterSlots
{
    /** @var array<int, Operand> */
    private array $values = [];

    /** @var array<int, list<Operand>> */
    private array $more = [];

    private int $position = 0;

    private bool $positional = true;

    private readonly ?int $variadic;

    /**
     * @param list<array{name: string|null, byRef: bool, variadic: bool}> $parameters
     */
    public function __construct(private readonly array $parameters)
    {
        $this->variadic = ArgumentLayout::variadicAt($parameters);
    }

    /**
     * A positional argument: the next parameter.
     */
    public function next(Operand $value): void
    {
        $this->place($this->position, $value);
        $this->position++;
    }

    /**
     * An array unpacked into the call: its elements go to every parameter
     * from here on, and none of them is the array itself.
     */
    public function everyRemaining(Operand $array): void
    {
        $this->positional = false;
        $last = max($this->position, count($this->parameters) - 1);

        for ($position = $this->position; $position <= $last; $position++) {
            $this->place($position, $array);
        }

        $this->position = $last + 1;
    }

    /**
     * A named argument: the parameter of that name, or the variadic one,
     * which collects names it does not declare. PHP refuses any other name,
     * so nothing receives it.
     */
    public function named(string $name, Operand $value): void
    {
        foreach ($this->parameters as $index => $parameter) {
            if ($parameter['name'] === $name && ! $parameter['variadic']) {
                $this->place($index, $value);

                return;
            }
        }

        if ($this->variadic !== null) {
            $this->place($this->variadic, $value);
        }
    }

    public function onto(CallTarget $target): CallTarget
    {
        $last = $this->values === [] ? -1 : max(array_keys($this->values));
        $arguments = [];

        // A parameter a named call skipped takes its default, which carries
        // nothing from the caller.
        for ($position = 0; $position <= $last; $position++) {
            $arguments[] = $this->values[$position] ?? new Operand\Literal(null);
        }

        // Values the target already had beside an argument stay with it.
        $more = $this->more;

        foreach ($target->moreArguments as $position => $operands) {
            $more[$position] = [...($more[$position] ?? []), ...$operands];
        }

        return $target->withParameterArguments($arguments, $more, $this->positional);
    }

    private function place(int $position, Operand $value): void
    {
        // A variadic parameter is an array of every argument from its
        // position on. It is never read by its keys (see ParameterKeyReads),
        // so collecting into it leaves the other parameters positional.
        if ($this->variadic !== null && $position > $this->variadic) {
            $position = $this->variadic;
        }

        if (! isset($this->values[$position])) {
            $this->values[$position] = $value;

            return;
        }

        $this->more[$position][] = $value;

        if ($position !== $this->variadic) {
            $this->positional = false;
        }
    }
}
