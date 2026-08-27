<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Constants declared anywhere in the scan, and the strings they hold.
 *
 * WordPress builds paths out of constants and almost nothing else:
 *
 * ```php
 * define( 'ACME_DIR', plugin_dir_path( __FILE__ ) );
 * …
 * require_once ACME_DIR . 'includes/settings.php';
 * ```
 *
 * 1,255 `define()` calls in the corpus, and `ABSPATH`, `WC_ABSPATH` and
 * `JETPACK__PLUGIN_DIR` between them account for over a thousand include sites.
 * Without this, include resolution stops at the first constant it meets.
 *
 * A set per name, not a value. A constant defined twice under different branches
 * genuinely holds either, and choosing one would be a guess — the same rule the
 * value resolver applies everywhere else.
 */
final class ConstantTable
{
    /**
     * Values a constant can hold, keyed by name.
     *
     * @var array<string, list<string>>
     */
    private array $values = [];

    /**
     * Names seen with a value this could not resolve.
     *
     * "Defined, but computed" and "never seen" are different answers: the first
     * means a resolution attempt is hopeless, the second that the definition may
     * simply be outside the scan.
     *
     * @var array<string, true>
     */
    private array $unresolved = [];

    /**
     * How many distinct values to keep before treating a name as unresolvable.
     *
     * A constant redefined more than a handful of times is one whose value
     * depends on configuration, and enumerating it buys nothing.
     */
    private const MAX_VALUES = 8;

    public function define(string $name, ?string $value): void
    {
        $name = self::normalise($name);

        if ($name === '') {
            return;
        }

        if ($value === null) {
            $this->unresolved[$name] = true;

            return;
        }

        if (in_array($value, $this->values[$name] ?? [], true)) {
            return;
        }

        $this->values[$name][] = $value;

        if (count($this->values[$name]) > self::MAX_VALUES) {
            unset($this->values[$name]);
            $this->unresolved[$name] = true;
        }
    }

    /**
     * @return list<string>
     */
    public function valuesOf(string $name): array
    {
        $name = self::normalise($name);

        if (isset($this->unresolved[$name])) {
            return [];
        }

        return $this->values[$name] ?? [];
    }

    public function isDefined(string $name): bool
    {
        $name = self::normalise($name);

        return isset($this->values[$name]) || isset($this->unresolved[$name]);
    }

    public function count(): int
    {
        return count($this->values);
    }

    /**
     * Constant names are case-sensitive in every version of PHP that matters,
     * but a leading namespace separator is not part of the name.
     */
    private static function normalise(string $name): string
    {
        return ltrim($name, '\\');
    }
}
