<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use PHPCfg\Operand;

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
     * Private properties declared with a literal array, by name, or false
     * once two declarations share the name.
     *
     * @var array<string, Operand|false>
     */
    private array $fixedProperties = [];

    /** @var array<string, true> property names code writes */
    private array $writtenProperties = [];

    private bool $anyPropertyWritten = false;

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
     * A class constant, `Acme_Notices::DISMISS`, under its class.
     *
     * A class name is not case-sensitive and a constant name is, so the key
     * lowers the one and keeps the other. `::` cannot be part of a global
     * constant's name, so the two never collide.
     */
    /**
     * A private property whose declared value is a literal array: see
     * {@see fixedPropertyDefault()}.
     */
    public function declareFixedProperty(string $name, Operand $default): void
    {
        $known = $this->fixedProperties[$name] ?? null;
        $this->fixedProperties[$name] = $known === null || $known === $default ? $default : false;
    }

    /**
     * Code writes a property of this name, or of a name it cannot read.
     */
    public function markPropertyWritten(?string $name): void
    {
        if ($name === null) {
            $this->anyPropertyWritten = true;

            return;
        }

        $this->writtenProperties[$name] = true;
    }

    /**
     * The declared literal array of the one private property with this name,
     * when nothing in the scan writes a property of that name. Its value is
     * then the declaration's, wherever it is read.
     */
    public function fixedPropertyDefault(string $name): ?Operand
    {
        if ($this->anyPropertyWritten || isset($this->writtenProperties[$name])) {
            return null;
        }

        $default = $this->fixedProperties[$name] ?? null;

        return $default instanceof Operand ? $default : null;
    }

    public function defineClassConstant(string $class, string $name, ?string $value): void
    {
        $this->define(self::classKey($class, $name), $value);
    }

    /**
     * @return list<string>
     */
    public function classConstantValuesOf(string $class, string $name): array
    {
        return $this->valuesOf(self::classKey($class, $name));
    }

    private static function classKey(string $class, string $name): string
    {
        return strtolower(ltrim($class, '\\')) . '::' . $name;
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
