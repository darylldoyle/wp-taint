<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * One of PHP's own functions, as reflection declares it.
 *
 * Generated into `registries/php-generated.toml` by
 * tools/generate-php-catalogue.php, and read only for a function the rest of
 * the catalogue has no model for. The rule is the declaration's: a function
 * declared to return something that can hold text returns the text of the
 * arguments that can hold it. `explode( ',', $_GET['ids'] )` is request data,
 * and so is `array_pop( $parts )`.
 *
 * An argument declared `int`, `float` or `bool` is a length, a count or a
 * flag. It cannot put text of its own into the result, so it is not listed.
 */
final class InternalFunction
{
    /**
     * @param list<int> $arguments     the parameters whose declared type can hold text
     * @param int|null  $argumentsFrom a variadic one: every argument from here on
     */
    public function __construct(
        public readonly Matcher $matcher,
        public readonly string $returns,
        public readonly array $arguments,
        public readonly ?int $argumentsFrom,
    ) {
    }

    /**
     * The positions of a call's arguments whose text can reach the result.
     *
     * @return list<int>
     */
    public function resolve(int $argumentCount): array
    {
        $positions = array_values(array_filter(
            $this->arguments,
            static fn (int $position): bool => $position < $argumentCount,
        ));

        for ($position = $this->argumentsFrom ?? $argumentCount; $position < $argumentCount; $position++) {
            if (! in_array($position, $positions, true)) {
                $positions[] = $position;
            }
        }

        return $positions;
    }
}
