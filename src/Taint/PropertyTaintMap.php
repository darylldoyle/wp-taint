<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Taint held by object properties, keyed by `class::property`.
 *
 * Properties are the one place taint has to outlive a single function body:
 * `$this->value = $_GET['x']` in one method and `echo $this->value` in another
 * is a single flow across two bodies. The interprocedural fixed point iterates
 * until this map stops changing.
 *
 * Not path-sensitive and not per-instance. A tainted `Foo::$value` taints every
 * read of `$value` on any `Foo`. Recorded in KNOWN_LIMITATIONS.md.
 */
final class PropertyTaintMap
{
    /** @var array<string, TaintSet> */
    private array $taint = [];

    public function get(?string $class, string $property): TaintSet
    {
        return $this->taint[self::key($class, $property)] ?? TaintSet::empty();
    }

    public function add(?string $class, string $property, TaintSet $taint): bool
    {
        if ($taint->isEmpty()) {
            return false;
        }

        $key = self::key($class, $property);
        $existing = $this->taint[$key] ?? TaintSet::empty();
        $merged = $existing->union($taint);

        if ($merged->equals($existing)) {
            return false;
        }

        $this->taint[$key] = $merged;

        return true;
    }

    private static function key(?string $class, string $property): string
    {
        return strtolower($class ?? '?') . '::' . $property;
    }
}
