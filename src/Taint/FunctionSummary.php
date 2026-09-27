<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * A function's taint behaviour, independent of any caller.
 *
 * Summaries are what make the analysis interprocedural without being
 * exponential: each function is analysed once per parameter, and every call
 * site instantiates the result rather than re-walking the body.
 *
 * @phpstan-type PropertyReference array{0: string|null, 1: string, 2: TaintSet}
 * @phpstan-type CaptureReference array{0: string, 1: string, 2: TaintSet}
 * @phpstan-type ScopeReference array{0: string, 1: string, 2: string, 3: int|string|null, 4: TaintSet}
 */
final class FunctionSummary
{
    /**
     * @param array<int, TaintSet>            $paramToReturn kinds that reach the return value from each parameter
     * @param array<int, list<SinkReference>> $paramToSink   sinks each parameter reaches
     * @param array<int, TaintSet>            $clears        kinds each parameter loses on the way to the return
     * @param array<int, array<int, TaintSet>> $paramToParam  kinds reaching each by-reference parameter, per source
     *                                                       parameter
     * @param array<int, TaintSet>            $sourcesToParam kinds a by-reference parameter receives from sources in
     *                                                       the body, independent of any argument
     */
    public function __construct(
        public readonly string $key,
        public readonly string $displayName,
        public readonly array $paramToReturn = [],
        public readonly array $paramToSink = [],
        public readonly array $clears = [],
        public readonly ?TaintSet $introducesOrNull = null,
        public readonly bool $imprecise = false,
        public readonly array $paramToParam = [],
        public readonly array $sourcesToParam = [],
        /**
         * Every return of this function carries a literal fragment.
         *
         * The interprocedural half of {@see LiteralAnchor}: a helper that
         * returns `'acme_' . $id` constrains what its callers can name, and
         * without this the caller cannot tell that from one that returns the
         * request verbatim.
         */
        public readonly bool $returnAnchored = false,
        /**
         * Properties each parameter is written into, and the kinds that reach
         * them.
         *
         * The write counterpart to {@see $paramToSink}. A probe run's property
         * map is sealed — its seed is a question, not something the code does —
         * so the flow into `$this->file` is recorded here and applied at the
         * call site with the taint the caller actually passed, less whatever
         * the body clears on the way. `$this->v = esc_html( $x )` stores no
         * HTML taint, whatever the caller hands in as `$x`.
         *
         * @var array<int, list<PropertyReference>>
         */
        public readonly array $paramToProperty = [],
        /**
         * Closure captures each parameter reaches.
         *
         * The capture counterpart to {@see $paramToProperty}. A closure's
         * captured scope is published by the run that seeds nothing, so a
         * capture whose value is the enclosing function's own parameter was
         * published clean whatever the caller passed. The probe run records
         * "parameter reaches capture `$name` of closure `key`" here, and the
         * call site publishes the caller's actual taint into the scope table,
         * less what the body clears, as for properties.
         *
         * @var array<int, list<CaptureReference>>
         */
        public readonly array $paramToCapture = [],
        /**
         * Shared scopes each parameter reaches.
         *
         * The scope counterpart to {@see $paramToCapture}, for the three ways
         * a function hands its variables to code outside it: a file it
         * includes sees its whole scope (`in`, the included file's `::{main}`
         * key, the variable's name, no array key); a template loaded with
         * `get_template_part()` sees `$args` (`in`, the template's key,
         * `args`, and the array key when the argument had one); and a closure
         * writes a by-reference capture back to the function that made it
         * (`out`, the closure's key, the captured name). A probe run records
         * these instead of publishing its seed, and the call site publishes
         * the caller's actual taint. The fifth part is the kinds that reach the
         * scope, and the caller publishes only those, as for properties.
         *
         * @var array<int, list<ScopeReference>>
         */
        public readonly array $paramToScope = [],
        /**
         * Kinds each parameter puts into the returned array's elements under a
         * computed key, as opposed to the value itself.
         *
         * `function build( $x ) { $a = array(); $a[] = $x; return $a; }`
         * returns an array whose own taint is nothing and whose elements are
         * $x. A caller reads the elements from its call result the way it
         * reads them from a local array, and a `foreach` over it sees the keys
         * it would see locally.
         *
         * @var array<int, TaintSet>
         */
        public readonly array $paramToReturnContainer = [],
        /**
         * Kinds each parameter puts into the returned array's elements under
         * a literal key, by key: `$a['title'] = $x; return $a;`.
         *
         * @var array<int, array<array-key, TaintSet>>
         */
        public readonly array $paramToReturnKeyed = [],
        /**
         * What the returned array's elements carry under a computed key
         * regardless of any argument, the elements' counterpart to
         * {@see introduces()}.
         */
        public readonly ?TaintSet $introducesContainerOrNull = null,
        /**
         * What the returned array's elements carry under each literal key
         * regardless of any argument.
         *
         * @var array<array-key, TaintSet>
         */
        public readonly array $introducesKeyed = [],
        /**
         * The keys this function reads each parameter through, for a
         * parameter it reads only through literal keys. See
         * {@see ParameterKeyReads}.
         *
         * @var array<int, list<array-key>>
         */
        public readonly array $parameterKeys = [],
    ) {
    }

    /**
     * The keys this function reads a parameter through, or null when it reads
     * the parameter whole.
     *
     * @return list<array-key>|null
     */
    public function keysReadFrom(int $parameterIndex): ?array
    {
        return $this->parameterKeys[$parameterIndex] ?? null;
    }

    public function returnContainerFor(int $parameterIndex): TaintSet
    {
        return $this->paramToReturnContainer[$parameterIndex] ?? TaintSet::empty();
    }

    /**
     * @return array<array-key, TaintSet>
     */
    public function returnKeyedFor(int $parameterIndex): array
    {
        return $this->paramToReturnKeyed[$parameterIndex] ?? [];
    }

    public function introducesContainer(): TaintSet
    {
        return $this->introducesContainerOrNull ?? TaintSet::empty();
    }

    /**
     * @return list<ScopeReference>
     */
    public function scopesFor(int $parameterIndex): array
    {
        return $this->paramToScope[$parameterIndex] ?? [];
    }

    /**
     * Which shared scope a reference names, as a string, for deduplicating.
     *
     * The kinds are left out: two references to the same scope are one
     * reference, carrying the kinds of both.
     *
     * @param array{0: string, 1: string, 2: string, 3: int|string|null, 4?: TaintSet} $reference
     */
    public static function scopeKey(array $reference): string
    {
        [$table, $key, $name, $arrayKey] = $reference;

        return implode("\0", [
            $table,
            $key,
            $name,
            $arrayKey === null ? '-' : (is_int($arrayKey) ? 'i' : 's') . $arrayKey,
        ]);
    }

    /**
     * @return list<PropertyReference>
     */
    public function propertiesFor(int $parameterIndex): array
    {
        return $this->paramToProperty[$parameterIndex] ?? [];
    }

    /**
     * @return list<CaptureReference> closure key, captured name, kinds
     */
    public function capturesFor(int $parameterIndex): array
    {
        return $this->paramToCapture[$parameterIndex] ?? [];
    }

    /**
     * What a by-reference parameter receives when `$source` is tainted.
     */
    public function byRefTaintFrom(int $source, int $target): TaintSet
    {
        return $this->paramToParam[$source][$target] ?? TaintSet::empty();
    }

    /**
     * What a by-reference parameter receives regardless of any argument — a
     * function that fills its out-parameter straight from `$_GET`.
     */
    public function byRefIntroduces(int $target): TaintSet
    {
        return $this->sourcesToParam[$target] ?? TaintSet::empty();
    }

    /**
     * @return list<int>
     */
    public function byRefParameters(): array
    {
        $indexes = array_keys($this->sourcesToParam);

        foreach ($this->paramToParam as $targets) {
            foreach (array_keys($targets) as $index) {
                $indexes[] = $index;
            }
        }

        $indexes = array_values(array_unique($indexes));
        sort($indexes);

        return $indexes;
    }

    public static function empty(string $key, string $displayName): self
    {
        return new self($key, $displayName);
    }

    /**
     * The worst of two bodies sharing one name.
     *
     * A tree that declares the same function twice — a conditionally-defined
     * shim, a vendored copy — used to have one copy speak for both, and it
     * could be the harmless one. Every taint-carrying field unions, `clears`
     * intersects (a parameter is only cleared if *every* body clears it), and
     * `returnAnchored` holds only when both bodies anchor — the caller sees
     * whichever behaviour is more dangerous, whichever file it came from.
     */
    public function union(self $other): self
    {
        $indexes = array_unique([...array_keys($this->paramToReturn), ...array_keys($other->paramToReturn)]);
        $paramToReturn = [];
        $clears = [];

        foreach ($indexes as $index) {
            $paramToReturn[$index] = $this->returnTaintFor($index)->union($other->returnTaintFor($index));
            $clears[$index] = $this->clearsFor($index)->intersect($other->clearsFor($index));
        }

        $paramToSink = [];

        foreach (array_unique([...array_keys($this->paramToSink), ...array_keys($other->paramToSink)]) as $index) {
            $merged = [];

            foreach ([...$this->sinksFor($index), ...$other->sinksFor($index)] as $sink) {
                $merged[$sink->identityKey()] ??= $sink;
            }

            ksort($merged);
            $paramToSink[$index] = array_values($merged);
        }

        $paramToParam = [];

        foreach (array_unique([...array_keys($this->paramToParam), ...array_keys($other->paramToParam)]) as $src) {
            $targets = array_unique([
                ...array_keys($this->paramToParam[$src] ?? []),
                ...array_keys($other->paramToParam[$src] ?? []),
            ]);

            foreach ($targets as $target) {
                $paramToParam[$src][$target] = $this->byRefTaintFrom($src, $target)
                    ->union($other->byRefTaintFrom($src, $target));
            }
        }

        $sourcesToParam = [];

        foreach (
            array_unique([...array_keys($this->sourcesToParam), ...array_keys($other->sourcesToParam)]) as $target
        ) {
            $sourcesToParam[$target] = $this->byRefIntroduces($target)->union($other->byRefIntroduces($target));
        }

        return new self(
            $this->key,
            $this->displayName,
            $paramToReturn,
            $paramToSink,
            $clears,
            $this->introduces()->union($other->introduces()),
            $this->imprecise || $other->imprecise,
            $paramToParam,
            $sourcesToParam,
            $this->returnAnchored && $other->returnAnchored,
            self::mergeProperties($this->paramToProperty, $other->paramToProperty),
            self::mergeCaptures($this->paramToCapture, $other->paramToCapture),
            self::mergeScopes($this->paramToScope, $other->paramToScope),
            self::mergeSets($this->paramToReturnContainer, $other->paramToReturnContainer),
            self::mergeKeyed($this->paramToReturnKeyed, $other->paramToReturnKeyed),
            $this->introducesContainer()->union($other->introducesContainer()),
            self::mergeKeyed([$this->introducesKeyed], [$other->introducesKeyed])[0] ?? [],
            self::mergeParameterKeys($this->parameterKeys, $other->parameterKeys),
        );
    }

    /**
     * A parameter is read only through keys when both bodies read it so, and
     * then through the keys of either.
     *
     * @param array<int, list<array-key>> $mine
     * @param array<int, list<array-key>> $theirs
     *
     * @return array<int, list<array-key>>
     */
    private static function mergeParameterKeys(array $mine, array $theirs): array
    {
        $merged = [];

        foreach ($mine as $index => $keys) {
            if (! isset($theirs[$index])) {
                continue;
            }

            $union = array_keys(array_fill_keys([...$keys, ...$theirs[$index]], true));
            sort($union);
            $merged[$index] = $union;
        }

        return $merged;
    }

    /**
     * @param array<int, TaintSet> $mine
     * @param array<int, TaintSet> $theirs
     *
     * @return array<int, TaintSet>
     */
    private static function mergeSets(array $mine, array $theirs): array
    {
        $result = $mine;

        foreach ($theirs as $index => $set) {
            $result[$index] = ($result[$index] ?? TaintSet::empty())->union($set);
        }

        ksort($result);

        return $result;
    }

    /**
     * @param array<int, array<array-key, TaintSet>> $mine
     * @param array<int, array<array-key, TaintSet>> $theirs
     *
     * @return array<int, array<array-key, TaintSet>>
     */
    private static function mergeKeyed(array $mine, array $theirs): array
    {
        $result = $mine;

        foreach ($theirs as $index => $keys) {
            foreach ($keys as $key => $set) {
                $result[$index][$key] = ($result[$index][$key] ?? TaintSet::empty())->union($set);
            }
        }

        ksort($result);

        return $result;
    }

    /**
     * Two bodies' property references, one per property, with the kinds of
     * both. The captures and scopes below merge the same way.
     *
     * @param array<int, list<PropertyReference>> $mine
     * @param array<int, list<PropertyReference>> $theirs
     *
     * @return array<int, list<PropertyReference>>
     */
    private static function mergeProperties(array $mine, array $theirs): array
    {
        $result = [];

        foreach (array_unique([...array_keys($mine), ...array_keys($theirs)]) as $index) {
            $merged = [];

            foreach ([...($mine[$index] ?? []), ...($theirs[$index] ?? [])] as $reference) {
                $id = self::propertyKey($reference);
                $kinds = ($merged[$id][2] ?? TaintSet::empty())->union($reference[2]);
                $merged[$id] = [$reference[0], $reference[1], $kinds];
            }

            ksort($merged);
            $result[$index] = array_values($merged);
        }

        return $result;
    }

    /**
     * @param array<int, list<CaptureReference>> $mine
     * @param array<int, list<CaptureReference>> $theirs
     *
     * @return array<int, list<CaptureReference>>
     */
    private static function mergeCaptures(array $mine, array $theirs): array
    {
        $result = [];

        foreach (array_unique([...array_keys($mine), ...array_keys($theirs)]) as $index) {
            $merged = [];

            foreach ([...($mine[$index] ?? []), ...($theirs[$index] ?? [])] as $reference) {
                $id = self::captureKey($reference);
                $kinds = ($merged[$id][2] ?? TaintSet::empty())->union($reference[2]);
                $merged[$id] = [$reference[0], $reference[1], $kinds];
            }

            ksort($merged);
            $result[$index] = array_values($merged);
        }

        return $result;
    }

    /**
     * @param array<int, list<ScopeReference>> $mine
     * @param array<int, list<ScopeReference>> $theirs
     *
     * @return array<int, list<ScopeReference>>
     */
    private static function mergeScopes(array $mine, array $theirs): array
    {
        $result = [];

        foreach (array_unique([...array_keys($mine), ...array_keys($theirs)]) as $index) {
            $merged = [];

            foreach ([...($mine[$index] ?? []), ...($theirs[$index] ?? [])] as $reference) {
                $id = self::scopeKey($reference);
                $kinds = ($merged[$id][4] ?? TaintSet::empty())->union($reference[4]);
                $merged[$id] = [$reference[0], $reference[1], $reference[2], $reference[3], $kinds];
            }

            ksort($merged);
            $result[$index] = array_values($merged);
        }

        return $result;
    }

    /**
     * The same references in the same places, with the same kinds.
     *
     * @template T of array<int, TaintSet|int|string|null>
     *
     * @param array<int, list<T>>   $mine
     * @param array<int, list<T>>   $theirs
     * @param callable(T): string   $identity
     * @param callable(T): TaintSet $kindsOf
     */
    private static function referencesEqual(
        array $mine,
        array $theirs,
        callable $identity,
        callable $kindsOf,
    ): bool {
        if (array_keys($mine) !== array_keys($theirs)) {
            return false;
        }

        foreach ($mine as $index => $references) {
            $a = self::kindsByIdentity($references, $identity, $kindsOf);
            $b = self::kindsByIdentity($theirs[$index] ?? [], $identity, $kindsOf);

            if (array_keys($a) !== array_keys($b)) {
                return false;
            }

            foreach ($a as $id => $kinds) {
                if (! $kinds->equals($b[$id] ?? TaintSet::empty())) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * @template T of array<int, TaintSet|int|string|null>
     *
     * @param list<T>               $references
     * @param callable(T): string   $identity
     * @param callable(T): TaintSet $kindsOf
     *
     * @return array<string, TaintSet> sorted by identity
     */
    private static function kindsByIdentity(array $references, callable $identity, callable $kindsOf): array
    {
        $result = [];

        foreach ($references as $reference) {
            $id = $identity($reference);
            $result[$id] = ($result[$id] ?? TaintSet::empty())->union($kindsOf($reference));
        }

        ksort($result);

        return $result;
    }

    /**
     * Kinds this function introduces regardless of its arguments, e.g. a
     * wrapper around get_option().
     */
    public function introduces(): TaintSet
    {
        return $this->introducesOrNull ?? TaintSet::empty();
    }

    public function returnTaintFor(int $parameterIndex): TaintSet
    {
        return $this->paramToReturn[$parameterIndex] ?? TaintSet::empty();
    }

    /**
     * @return list<SinkReference>
     */
    public function sinksFor(int $parameterIndex): array
    {
        return $this->paramToSink[$parameterIndex] ?? [];
    }

    public function clearsFor(int $parameterIndex): TaintSet
    {
        return $this->clears[$parameterIndex] ?? TaintSet::empty();
    }

    /**
     * Structural equality, used by the interprocedural fixed point to decide
     * whether another round is needed.
     */
    public function equals(self $other): bool
    {
        if ($this->imprecise !== $other->imprecise || ! $this->introduces()->equals($other->introduces())) {
            return false;
        }

        if ($this->returnAnchored !== $other->returnAnchored) {
            return false;
        }

        if (array_keys($this->paramToReturn) !== array_keys($other->paramToReturn)) {
            return false;
        }

        foreach ($this->paramToReturn as $index => $set) {
            if (! $set->equals($other->paramToReturn[$index] ?? TaintSet::empty())) {
                return false;
            }
        }

        foreach ($this->paramToSink as $index => $sinks) {
            $mine = array_map(static fn (SinkReference $s): string => $s->identityKey(), $sinks);
            $theirs = array_map(
                static fn (SinkReference $s): string => $s->identityKey(),
                $other->paramToSink[$index] ?? [],
            );

            sort($mine);
            sort($theirs);

            if ($mine !== $theirs) {
                return false;
            }
        }

        // The by-reference halves drive the fixed point too: a summary whose
        // out-parameter behaviour is still growing is not settled, however
        // stable its return value looks.
        if (! self::setsEqual($this->sourcesToParam, $other->sourcesToParam)) {
            return false;
        }

        if (array_keys($this->paramToParam) !== array_keys($other->paramToParam)) {
            return false;
        }

        foreach ($this->paramToParam as $source => $targets) {
            if (! self::setsEqual($targets, $other->paramToParam[$source] ?? [])) {
                return false;
            }
        }

        // Same reason as the by-reference halves: a summary whose property
        // writes are still being discovered is not settled. The captures and
        // shared scopes likewise, and the kinds reaching each of the three.
        if (
            ! self::referencesEqual(
                $this->paramToProperty,
                $other->paramToProperty,
                self::propertyKey(...),
                /** @param PropertyReference $reference */
                static fn (array $reference): TaintSet => $reference[2],
            )
            || ! self::referencesEqual(
                $this->paramToCapture,
                $other->paramToCapture,
                self::captureKey(...),
                /** @param CaptureReference $reference */
                static fn (array $reference): TaintSet => $reference[2],
            )
            || ! self::referencesEqual(
                $this->paramToScope,
                $other->paramToScope,
                self::scopeKey(...),
                /** @param ScopeReference $reference */
                static fn (array $reference): TaintSet => $reference[4],
            )
        ) {
            return false;
        }

        // The returned array's elements drive the fixed point as its value
        // does.
        if (
            ! $this->introducesContainer()->equals($other->introducesContainer())
            || ! self::setsEqual($this->paramToReturnContainer, $other->paramToReturnContainer)
            || ! self::setsEqual($this->introducesKeyed, $other->introducesKeyed)
            || array_keys($this->paramToReturnKeyed) !== array_keys($other->paramToReturnKeyed)
        ) {
            return false;
        }

        foreach ($this->paramToReturnKeyed as $index => $keys) {
            if (! self::setsEqual($keys, $other->paramToReturnKeyed[$index] ?? [])) {
                return false;
            }
        }

        if ($this->parameterKeys !== $other->parameterKeys) {
            return false;
        }

        return count($this->paramToSink) === count($other->paramToSink);
    }

    /**
     * @param PropertyReference $property
     */
    private static function propertyKey(array $property): string
    {
        return strtolower($property[0] ?? '?') . '::' . $property[1];
    }

    /**
     * @param CaptureReference $capture
     */
    private static function captureKey(array $capture): string
    {
        return $capture[0] . '::' . $capture[1];
    }

    /**
     * @param array<array-key, TaintSet> $a
     * @param array<array-key, TaintSet> $b
     */
    private static function setsEqual(array $a, array $b): bool
    {
        if (array_keys($a) !== array_keys($b)) {
            return false;
        }

        foreach ($a as $index => $set) {
            if (! $set->equals($b[$index] ?? TaintSet::empty())) {
                return false;
            }
        }

        return true;
    }
}
