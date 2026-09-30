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
    /**
     * Whether writes into this copy are discarded.
     *
     * A parameter probe seeds one parameter with every taint kind to find out
     * what the function does with it. That seed is a question, not a fact, and
     * committing its answer to a map the whole scan shares turns it into one:
     *
     *     function __construct( $file, $level ) {
     *         $this->file = $file;          // probed with every kind
     *     }
     *
     * left `MC4WP_Debug_Log::$file` holding html, sql, path, shell, eval and
     * ten more, permanently, so `fopen( $this->file, 'a' )` two hundred lines
     * away was a path-traversal finding. 334 of the corpus's 1,414 findings
     * rested on a seed like that one — Twig's compiler as an eval sink,
     * phpseclib's Barrett reduction, monolog's configured `proc_open()`.
     *
     * The property map records what the baseline run — the one that seeds
     * nothing and reads the body as written — actually saw.
     */
    private bool $sealed = false;

    /** @var array<string, bool> */
    private array $anchored = [];

    /**
     * The allocation sites each property was written on, kept as writes are
     * tracked. See {@see allocatedOwners()}.
     *
     * @var array<string, list<string>>
     */
    private array $allocated = [];

    /**
     * Each property's value as a shape: its own taint on top and, for an
     * array, its elements under their keys, so a read of `$this->opts['mode']`
     * sees only what `'mode'` was given.
     *
     * @var array<string, Shape>
     */
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

    /**
     * Shared with every copy made by clone or {@see sealed()}: a probe run
     * reads through a sealed copy, and those reads are the function's too.
     */
    private ?ReadLog $log = null;

    /**
     * Record every read from now on. See {@see ReadLog}.
     */
    public function recordReadsInto(?ReadLog $log): void
    {
        $this->log = $log;
    }

    /**
     * Everything the property holds, by any route.
     */
    public function get(?string $class, string $property): TaintSet
    {
        return $this->valueOf($class, $property)->flatten();
    }

    /**
     * The property's value: its own taint, and its elements under their keys.
     */
    public function valueOf(?string $class, string $property): Shape
    {
        $this->log?->record('p:' . self::key($class, $property));

        return $this->taint[self::key($class, $property)] ?? Shape::empty();
    }

    /**
     * The allocation sites whose objects had this property written: see
     * {@see \Enshrined\WpTaint\Cfg\ConstantTable::allocationSite()}.
     *
     * @return list<string>
     */
    public function allocatedOwners(string $property): array
    {
        // Its own entry, not `p*:`. The answer moves only when a site is
        // written for the first time, and `p*:` moves whenever any slot of
        // the name does: every reader of `$this->settings` ran again each
        // time one settings object changed.
        $this->log?->record('pa:' . $property);

        return $this->allocated[$property] ?? [];
    }

    /**
     * What a read of `$property` sees across `$slots`: the values joined,
     * whether every slot's writes were anchored, and whether the tracked
     * slots all hold nothing, or null when no slot was tracked. These are
     * the three answers a read gives the dataflow, {@see LiteralAnchor} and
     * {@see OriginClassifier}. It logs the reads those make.
     *
     * The write's origin is left out. Two receivers whose slots hold the
     * same value can still name different writes as its origin, and a trace
     * is not a reason to run a method again.
     *
     * @param list<string|null> $slots
     *
     * @return array{Shape, bool, bool|null}
     */
    public function viewOf(array $slots, string $property): array
    {
        $value = Shape::empty();
        $anchored = true;
        $tracked = false;
        $clean = true;

        foreach ($slots as $slot) {
            $each = $this->valueOf($slot, $property);
            $value = $value->join($each);
            $anchored = $anchored && $this->isAnchored($slot, $property);

            if ($this->isTracked($slot, $property)) {
                $tracked = true;
                $clean = $clean && $each->flatten()->isEmpty();
            }
        }

        return [$value, $anchored, $tracked ? $clean : null];
    }

    public function isTracked(?string $class, string $property): bool
    {
        $this->log?->record('p:' . self::key($class, $property));

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
        $this->log?->record('p*:' . $property);

        $suffix = '::' . $property;
        $seen = false;

        foreach (array_keys($this->tracked) as $key) {
            if (! str_ends_with($key, $suffix)) {
                continue;
            }

            $seen = true;

            if (! ($this->taint[$key] ?? Shape::empty())->isEmpty()) {
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
        $this->log?->record('p:' . self::key($class, $property));

        return $this->origins[self::key($class, $property)] ?? [];
    }

    /**
     * Was every value ever written to this property anchored by a literal?
     *
     * A property nothing was recorded for answers true: not knowing is not the
     * same as knowing it is unanchored, and claiming otherwise turns every
     * property this engine cannot see into a finding.
     *
     * @see LiteralAnchor
     */
    public function isAnchored(?string $class, string $property): bool
    {
        $this->log?->record('p:' . self::key($class, $property));

        return $this->anchored[self::key($class, $property)] ?? true;
    }

    /**
     * Record whether a write to this property carried a literal fragment.
     *
     * AND-ed across every write, because one assignment of the raw request is
     * enough to make the property useless as an anchor.
     */
    public function recordAnchor(?string $class, string $property, bool $anchored): void
    {
        if ($this->sealed) {
            return;
        }

        $key = self::key($class, $property);
        $this->anchored[$key] = ($this->anchored[$key] ?? true) && $anchored;
    }

    /**
     * Record that a property was written, whatever the value's taint.
     */
    public function track(?string $class, string $property): void
    {
        if ($this->sealed) {
            return;
        }

        $this->startTracking(self::key($class, $property));
    }

    /**
     * A copy whose writes go nowhere.
     *
     * Shallow, because PHP copies an array only when it is written to and this
     * copy never writes one — so sealing is free, and stays free however large
     * the map has grown.
     */
    public function sealed(): self
    {
        $copy = clone $this;
        $copy->sealed = true;

        return $copy;
    }

    /**
     * @param list<TraceStep> $origin the trace of the write that produced this taint
     */
    public function add(?string $class, string $property, Shape $value, array $origin = []): bool
    {
        if ($this->sealed) {
            return false;
        }

        // Another run reads this: a loop's element numbers are the writing
        // run's own, see TaintSet::withoutElements(), and a write belongs to
        // the graph it was made in.
        $value = $value->mapSets(static fn (TaintSet $taint): TaintSet => $taint->withoutElements());

        $this->track($class, $property);

        if ($value->isEmpty()) {
            return false;
        }

        $key = self::key($class, $property);

        if ($origin !== []) {
            $this->origins[$key] = self::preferredOrigin($this->origins[$key] ?? [], $origin);
        }

        $existing = $this->taint[$key] ?? Shape::empty();
        $merged = $existing->join($value);

        // A join that adds nothing hands back the shape it joined into.
        if ($merged === $existing) {
            return false;
        }

        $this->taint[$key] = $merged;

        return true;
    }

    /**
     * Fold another map into this one.
     *
     * Used to merge what each `--jobs` worker recorded. Every half only ever
     * grows and the origin tie-break is total, so the order the merge happens
     * in cannot change the result.
     */
    public function mergeFrom(self $other): bool
    {
        return $this->mergeChangedKeys($other) !== [];
    }

    /**
     * Merge, and say which entries moved, as `class::property` keys.
     *
     * @return list<string>
     */
    public function mergeChangedKeys(self $other): array
    {
        return $this->mergeChanges($other)['keys'];
    }

    /**
     * Merge, and say which entries moved, as `class::property` keys, and
     * which properties were written on an allocation site for the first
     * time, which is when {@see allocatedOwners()} gives another answer.
     *
     * @return array{keys: list<string>, allocated: list<string>}
     */
    public function mergeChanges(self $other): array
    {
        $changed = [];
        $allocated = [];

        foreach (array_keys($other->tracked) as $key) {
            if (! isset($this->tracked[$key])) {
                $property = $this->startTracking($key);
                $changed[$key] = true;

                if ($property !== null) {
                    $allocated[$property] = true;
                }
            }
        }

        foreach ($other->origins as $key => $origin) {
            $current = $this->origins[$key] ?? [];
            $preferred = self::preferredOrigin($current, $origin);

            // By signature, never by identity. Two workers analysing the same
            // write produce equal traces made of *different* TraceStep objects,
            // and `!==` on arrays of objects compares those by identity — so
            // every round would report a change and the fixed point would never
            // settle.
            if (self::signature($preferred) !== self::signature($current)) {
                $this->origins[$key] = $preferred;
                $changed[$key] = true;
            }
        }

        foreach ($other->taint as $key => $value) {
            $existing = $this->taint[$key] ?? Shape::empty();
            $merged = $existing->join($value);

            if ($merged !== $existing) {
                $this->taint[$key] = $merged;
                $changed[$key] = true;
            }
        }

        // AND-ed, the same way recordAnchor accumulates it: one unanchored
        // write anywhere makes the property unanchored everywhere, and that
        // verdict has to survive the merge or a caller that anchors the name in
        // a different function from the write loses its vote every round. This
        // is what carries `new Setting( $_POST['name'] )` from the constructor
        // that stores it to the method that writes the option.
        foreach ($other->anchored as $key => $anchored) {
            $merged = ($this->anchored[$key] ?? true) && $anchored;

            if ($merged !== ($this->anchored[$key] ?? true)) {
                $this->anchored[$key] = $merged;
                $changed[$key] = true;
            }
        }

        return ['keys' => array_keys($changed), 'allocated' => array_map('strval', array_keys($allocated))];
    }

    /**
     * Which of two traces for the same property to keep.
     *
     * "Whichever arrived first" is the obvious rule and it is wrong: a property
     * written in two places has its writes split across `--jobs` shards, so
     * which one arrives first depends on the worker count. Elementor's
     * `Base::$path` produced a seven-step trace at `--jobs=1` and a five-step
     * one at `--jobs=2` — the same finding, explained less well, for no reason
     * the reader could see.
     *
     * The rule is the lexicographically smallest signature. Not the longest,
     * which is what the finding dedup prefers and what the reader would rather
     * read: `$this->value = $this->value . $i` in a loop grows its own origin
     * by a step every round, so "longest wins" never reaches a fixed point and
     * the interprocedural loop runs to its cap.
     *
     * Smallest is stable. A trace that extends another sorts after it, so a
     * later, longer origin cannot displace the one already chosen, and the
     * choice is the same however the writes were sharded.
     *
     * @param list<TraceStep> $current
     * @param list<TraceStep> $candidate
     *
     * @return list<TraceStep>
     */
    private static function preferredOrigin(array $current, array $candidate): array
    {
        if ($current === []) {
            return $candidate;
        }

        if ($candidate === []) {
            return $current;
        }

        return self::signature($current) <= self::signature($candidate) ? $current : $candidate;
    }

    /**
     * @param list<TraceStep> $origin
     */
    private static function signature(array $origin): string
    {
        $parts = [];

        foreach ($origin as $step) {
            $parts[] = implode(':', [$step->file, (string) $step->line, (string) $step->column, $step->description]);
        }

        return implode("\0", $parts);
    }

    /**
     * Track a `class::property` key, and index it by property when its owner
     * is an allocation site. Rebuilding the index from every tracked key
     * whenever one was added cost up to 10.8 seconds a scan.
     *
     * @return string|null the property, when the key is a new allocation site's
     */
    private function startTracking(string $key): ?string
    {
        if (isset($this->tracked[$key])) {
            return null;
        }

        $this->tracked[$key] = true;
        $at = strrpos($key, '::');

        if ($at === false || ! str_contains(substr($key, 0, $at), '@')) {
            return null;
        }

        $property = substr($key, $at + 2);
        $this->allocated[$property][] = substr($key, 0, $at);

        return $property;
    }

    private static function key(?string $class, string $property): string
    {
        // `class#method` names the objects a method runs on, which keep their
        // properties under their class.
        $at = $class === null ? false : strpos($class, '#');

        return strtolower($at === false ? ($class ?? '?') : substr($class, 0, $at)) . '::' . $property;
    }
}
