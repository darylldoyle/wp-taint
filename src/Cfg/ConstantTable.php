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
     * Class constants declared as a list of literal strings, by class and
     * name, or false once a declaration of that name is anything else.
     *
     * @var array<string, list<string>|false>
     */
    private array $lists = [];

    /**
     * Private properties declared with a literal array, by name, or false
     * once two declarations share the name.
     *
     * @var array<string, Operand|false>
     */
    private array $fixedProperties = [];

    /** @var array<string, true> property names code writes */
    private array $writtenProperties = [];

    /** @var array<string, array<string, array<string, true>>> property => owner class => allocation sites */
    private array $allocations = [];

    /** @var array<string, array{string, string}> allocation site => the class and method its `new` is in */
    private array $makers = [];

    /** @var array<string, array<string, true>> property or '*' => owner class or '*' => true */
    private array $notAllocated = [];

    /** @var array<string, string|null> holder class and property => its one site, see allocationFor() */
    private array $allocationFor = [];

    /** @var array<string, string|null> function key => the allocation site of the object it returns */
    private array $returnedSites = [];

    /** @var array<string, true> the allocation sites of `(object)` cast lines */
    private array $castSites = [];

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

    /**
     * The key of the objects one `new` expression creates: its class, file and
     * line. Every object made there shares the key.
     */
    public static function allocationSite(string $class, string $file, int $line): string
    {
        return strtolower(ltrim($class, '\\')) . '@' . $file . ':' . $line;
    }

    /**
     * The class of an allocation site's objects, or null for a class key.
     */
    public static function allocatedClass(string $key): ?string
    {
        $at = strpos($key, '@');

        return $at === false ? null : substr($key, 0, $at);
    }

    /**
     * The key of the objects one `new` line makes while its method runs on
     * an object of `$holder`: see {@see holderOf()}.
     */
    public static function siteFor(string $site, string $holder): string
    {
        return $site . '^' . strtolower(ltrim($holder, '\\'));
    }

    /**
     * The class an allocation site's key is for, or null for a key that
     * names none and for a class key.
     *
     * A `new` in a method that runs on objects of more than one class makes
     * a different object for each class. Its key then ends in the class the
     * run is on. The class stands for its descendants too, as a class key
     * does.
     *
     * ```php
     * trait Stats_Queries {
     *     protected function init() { $this->query = new Sql_Query(); }
     * }
     * class Orders_Stats { use Stats_Queries; }
     * class Taxes_Stats { use Stats_Queries; }
     * ```
     *
     * `init()` makes one query for an Orders_Stats object and another for a
     * Taxes_Stats object. Their keys end `^orders_stats` and `^taxes_stats`.
     */
    public static function holderOf(string $key): ?string
    {
        // A class name holds no `:`, so a class follows the line number.
        $line = strrpos($key, ':');
        $at = $line === false ? false : strpos($key, '^', $line);

        return $at === false || ! str_contains($key, '@') ? null : substr($key, $at + 1);
    }

    /**
     * An allocation site's key without the class {@see holderOf()} names.
     */
    public static function unqualifiedSite(string $key): string
    {
        $holder = self::holderOf($key);

        return $holder === null ? $key : substr($key, 0, -strlen($holder) - 1);
    }

    /**
     * `$this->subquery = new SqlQuery( ... )`, seen in a method of `$owner`.
     *
     * The allocation site is the object, for a property only ever given a new
     * object of a named class: see {@see allocationsOf()}. `$method` is the
     * instance method the `new` is in, and null for a closure or a static
     * method: see {@see makerOf()}.
     */
    public function recordPropertyAllocation(string $owner, string $name, string $site, ?string $method = null): void
    {
        $this->allocations[$name][strtolower($owner)][$site] = true;

        if ($method !== null) {
            $this->makers[$site] ??= [$owner, $method];
        }
    }

    /**
     * The class and instance method an allocation site's `new` is in, when a
     * property is given its object there. Whether the method runs on objects
     * of more than one class decides whether the site's key names the class
     * the run is on: see {@see holderOf()}.
     *
     * @return array{string, string}|null
     */
    public function makerOf(string $site): ?array
    {
        return $this->makers[$site] ?? null;
    }

    /**
     * A function whose every `return` hands back the object one `new` line
     * or `(object)` cast in it makes.
     *
     * ```php
     * function acme_make_row() {
     *     $row = (object) array( 'title' => '' );
     *     $row->title = $_GET['t'];
     *     return $row;
     * }
     * ```
     */
    public function recordReturnedSite(string $function, string $site): void
    {
        $key = strtolower($function);

        // Two declarations of one function that return different objects
        // return neither for sure.
        $this->returnedSites[$key] = array_key_exists($key, $this->returnedSites)
            && $this->returnedSites[$key] !== $site ? null : $site;
    }

    /**
     * The allocation site of the object a function returns: see
     * {@see recordReturnedSite()}.
     */
    public function returnedSite(string $function): ?string
    {
        return $this->returnedSites[strtolower($function)] ?? null;
    }

    /**
     * An `(object)` cast line, as the allocation site of the stdClass
     * objects it makes.
     */
    public function recordCastSite(string $site): void
    {
        $this->castSites[$site] = true;
    }

    /**
     * Whether an allocation site is an `(object)` cast line.
     */
    public function isCastSite(string $site): bool
    {
        return isset($this->castSites[$site]);
    }

    /**
     * A property given anything but a new object of a named class: a value, a
     * reference, a copy of another object. `$owner` is the class whose method
     * gives it through `$this`, and null for any other receiver, which could be
     * an object of any class. `$name` is null for a computed name, which could
     * be any property.
     */
    public function markPropertyNotAllocated(?string $owner, ?string $name): void
    {
        $this->notAllocated[$name ?? '*'][$owner === null ? '*' : strtolower($owner)] = true;
    }

    /**
     * The allocation sites a property of this name is given, by the class
     * whose method gives it through `$this`, and the classes that give it
     * something else. Null when a receiver of any class is given something
     * else under this name.
     *
     * @return array{array<string, array<string, true>>, array<string, true>}|null
     *         owner class => sites, and the owner classes that give anything else
     */
    public function allocationsOf(string $name): ?array
    {
        $other = ($this->notAllocated[$name] ?? []) + ($this->notAllocated['*'] ?? []);

        if (isset($other['*'])) {
            return null;
        }

        return [$this->allocations[$name] ?? [], $other];
    }

    /**
     * The one allocation site `$this->name` can hold on an object of
     * `$holder`: the sites the scan gives a property of that name from a
     * method of one of `$related`. Null when there are several, or when one
     * of them gives the property anything else.
     *
     * `$related` is the classes whose methods can run on such an object:
     * see {@see \Enshrined\WpTaint\Taint\UserFunctionTable::relatedClasses()}.
     * It depends on `$holder` alone, so the answer is kept per holder and
     * property.
     *
     * @param array<string, true> $related lower-case class names
     */
    public function allocationFor(string $holder, string $name, array $related): ?string
    {
        $key = strtolower($holder) . '::' . $name;

        if (array_key_exists($key, $this->allocationFor)) {
            return $this->allocationFor[$key];
        }

        return $this->allocationFor[$key] = $this->onlyAllocation($name, $related);
    }

    /**
     * @param array<string, true> $related
     */
    private function onlyAllocation(string $name, array $related): ?string
    {
        $given = $this->allocationsOf($name);

        if ($given === null) {
            return null;
        }

        [$allocated, $other] = $given;
        $sites = [];

        foreach (array_keys($related) as $class) {
            if (isset($other[$class])) {
                return null;
            }

            $sites += $allocated[$class] ?? [];
        }

        return count($sites) === 1 ? (string) array_key_first($sites) : null;
    }

    public function defineClassConstant(string $class, string $name, ?string $value): void
    {
        $this->define(self::classKey($class, $name), $value);
    }

    /**
     * A class constant declared as an array: the strings in it, or null when
     * one of its values is not a literal string.
     *
     * `const TAGS = array( 'div', 'p' );` is how a class keeps an allowlist.
     * A second declaration under the same name that differs leaves the list
     * unknown, as it does for a scalar.
     *
     * @param list<string>|null $values
     */
    public function defineClassConstantList(string $class, string $name, ?array $values): void
    {
        $key = self::classKey($class, $name);
        $known = $this->lists[$key] ?? null;

        $this->lists[$key] = $values === null || ($known !== null && $known !== $values) ? false : $values;
    }

    /**
     * The strings a class constant's array holds, or null when it is not
     * known to be a list of literal strings.
     *
     * @return list<string>|null
     */
    public function classConstantListOf(string $class, string $name): ?array
    {
        $values = $this->lists[self::classKey($class, $name)] ?? null;

        return is_array($values) ? $values : null;
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
