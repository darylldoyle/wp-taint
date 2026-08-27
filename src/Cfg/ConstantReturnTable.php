<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Functions whose every `return` yields the same constant string.
 *
 * ```php
 * public function plugin_path() {
 *     return untrailingslashit( plugin_dir_path( WC_PLUGIN_FILE ) );
 * }
 * …
 * include WC()->plugin_path() . '/includes/admin/views/html-report-by-date.php';
 * ```
 *
 * A call in the middle of a path was the last mechanical thing stopping include
 * resolution — 12% of what still would not resolve, and WooCommerce's own
 * accessor is most of it.
 *
 * ## Why this is not on FunctionSummary
 *
 * The plan put it there, and that would have been the wrong place. Summaries are
 * produced by the taint analysis, and the include graph is built *before* the
 * analysis runs, because which file an include loads is a static fact. Putting a
 * value the resolver needs behind a summary would have made the include graph
 * depend on the thing it feeds.
 *
 * This is a static fact too, so it is collected the way constants are: two
 * passes over the same bodies, before anything else starts.
 */
final class ConstantReturnTable
{
    /** @var array<string, string> function key => the string it always returns */
    private array $returns = [];

    /**
     * Method names declared exactly once across the scan.
     *
     * `WC()->plugin_path()` names a method on a receiver whose class the value
     * resolver cannot see — `WC()` returns an instance, not a string. When only
     * one class in the scan declares `plugin_path`, there is nothing to be
     * ambiguous about; when two do, the call stays unresolved rather than
     * picking one.
     *
     * @var array<string, string|false> method name => owning key, or false when ambiguous
     */
    private array $byMethod = [];

    public function record(string $key, string $value): void
    {
        $this->returns[strtolower($key)] = $value;

        $position = strpos($key, '::');

        if ($position === false) {
            return;
        }

        $method = strtolower(substr($key, $position + 2));

        $this->byMethod[$method] = isset($this->byMethod[$method])
            ? false
            : strtolower($key);
    }

    public function forFunction(string $name): ?string
    {
        return $this->returns[strtolower(ltrim($name, '\\'))] ?? null;
    }

    /**
     * The constant return of a method named this, when exactly one class
     * declares it.
     */
    public function forUniqueMethod(string $method): ?string
    {
        $key = $this->byMethod[strtolower($method)] ?? false;

        return $key === false ? null : ($this->returns[$key] ?? null);
    }

    public function count(): int
    {
        return count($this->returns);
    }
}
