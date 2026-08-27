<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * A function's taint behaviour, independent of any caller.
 *
 * Summaries are what make the analysis interprocedural without being
 * exponential: each function is analysed once per parameter, and every call
 * site instantiates the result rather than re-walking the body.
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
    ) {
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

        return count($this->paramToSink) === count($other->paramToSink);
    }

    /**
     * @param array<int, TaintSet> $a
     * @param array<int, TaintSet> $b
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
