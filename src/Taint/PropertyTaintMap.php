<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\TraceStep;

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
 *
 * Each entry carries the trace of the write that tainted it, so a finding whose
 * flow enters through a property read still shows where the value came from. A
 * trace that begins "read from property $x" and stops there tells a reviewer
 * nothing, and a finding a reviewer cannot judge is one they learn to ignore.
 */
final class PropertyTaintMap
{
    /** @var array<string, TaintSet> */
    private array $taint = [];

    /**
     * Every property the scan saw written, whether or not the value was
     * tainted.
     *
     * "We tracked this and it was clean" and "we never saw it" are different
     * answers, and {@see OriginClassifier} needs to tell them apart.
     *
     * @var array<string, true>
     */
    private array $tracked = [];

    /**
     * The trace of the write that put taint into each property.
     *
     * @var array<string, list<TraceStep>>
     */
    private array $origins = [];

    public function get(?string $class, string $property): TaintSet
    {
        return $this->taint[self::key($class, $property)] ?? TaintSet::empty();
    }

    public function isTracked(?string $class, string $property): bool
    {
        return isset($this->tracked[self::key($class, $property)]);
    }

    /**
     * Whether a property of this *name* was written somewhere in the scan and
     * carries no taint under any class.
     *
     * Traits are why this exists. `$this->_table_img_optming` is read inside a
     * trait method — whose declaring class, as far as the CFG is concerned, is
     * the trait — and written in the class that uses the trait. Keyed lookup
     * misses across that boundary, so the shape rules saw a property they had
     * "never seen written" and fired. LiteSpeed Cache alone produced 42
     * findings that way.
     *
     * Only the shape rules consult this, and only to decide whether to stay
     * quiet. It never clears real taint, so the cost of being wrong is a missed
     * shape finding rather than a missed flow.
     */
    public function isCleanEverywhere(string $property): bool
    {
        $suffix = '::' . $property;
        $seen = false;

        foreach (array_keys($this->tracked) as $key) {
            if (! str_ends_with($key, $suffix)) {
                continue;
            }

            $seen = true;

            if (! ($this->taint[$key] ?? TaintSet::empty())->isEmpty()) {
                return false;
            }
        }

        return $seen;
    }

    /**
     * The trace of the write that tainted a property, for prefixing onto a
     * finding whose flow enters by reading it.
     *
     * @return list<TraceStep>
     */
    public function originOf(?string $class, string $property): array
    {
        return $this->origins[self::key($class, $property)] ?? [];
    }

    /**
     * Record that a property was written, whatever the value's taint.
     */
    public function track(?string $class, string $property): void
    {
        $this->tracked[self::key($class, $property)] = true;
    }

    /**
     * @param list<TraceStep> $origin the trace of the write that produced this taint
     */
    public function add(?string $class, string $property, TaintSet $taint, array $origin = []): bool
    {
        $this->track($class, $property);

        if ($taint->isEmpty()) {
            return false;
        }

        $key = self::key($class, $property);

        // Keep the first origin recorded for a property. Writes are visited in
        // a fixed order, so this is deterministic; taking the newest would
        // change with whichever round the write happened to land in.
        if ($origin !== [] && ! isset($this->origins[$key])) {
            $this->origins[$key] = $origin;
        }
        $existing = $this->taint[$key] ?? TaintSet::empty();
        $merged = $existing->union($taint);

        if ($merged->equals($existing)) {
            return false;
        }

        $this->taint[$key] = $merged;

        return true;
    }

    /**
     * Fold another map into this one.
     *
     * Used to merge what each `--jobs` worker recorded. Both halves only ever
     * grow, so the merge is a union and the order it happens in cannot change
     * the result.
     */
    public function mergeFrom(self $other): bool
    {
        $changed = false;

        foreach (array_keys($other->tracked) as $key) {
            if (! isset($this->tracked[$key])) {
                $this->tracked[$key] = true;
                $changed = true;
            }
        }

        foreach ($other->origins as $key => $origin) {
            if (! isset($this->origins[$key])) {
                $this->origins[$key] = $origin;
                $changed = true;
            }
        }

        foreach ($other->taint as $key => $taint) {
            $existing = $this->taint[$key] ?? TaintSet::empty();
            $merged = $existing->union($taint);

            if (! $merged->equals($existing)) {
                $this->taint[$key] = $merged;
                $changed = true;
            }
        }

        return $changed;
    }

    private static function key(?string $class, string $property): string
    {
        return strtolower($class ?? '?') . '::' . $property;
    }
}
