<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * What a method's own run read and did through `$this`.
 *
 * A method call on another object runs the callee on that receiver: see
 * {@see FunctionAnalysis::variantOf()}. Most callees do the same thing
 * there as in their own run, because the receiver's properties hold what
 * the class's do. A variant then costs a full summary and changes nothing.
 * This record lets a call tell, without running the variant, whether the
 * method's own summary is already the answer:
 *
 * ```php
 * class Acme_Store extends Acme_Query {
 *     public function run() {
 *         $this->add( 'select', 'id' );   // add() reads nothing of $this
 *     }
 * }
 * ```
 *
 * The own summary answers for receiver R when every property the run read
 * through `$this` holds the same on R, every `$this->name` that held one
 * allocation site holds the same one on R, and every method it called on
 * `$this` answers the same on R. A run that reached `$this` another way, or
 * that wrote `$this` from a run whose writes are held back, never answers
 * for another receiver.
 */
final class ReceiverView
{
    /**
     * The answers a read of a property gives, as {@see PropertyTaintMap::viewOf()}
     * returns them: the value, whether every write was anchored, and whether
     * the tracked slots hold nothing. A view keeps an answer only when the run
     * read it. Only {@see LiteralAnchor} reads the second and only
     * {@see OriginClassifier} the third, and a WPForms field's `$defaults`,
     * clean everywhere, differed in both from one field class to the next.
     */
    public const VALUE = 0;

    public const ANCHORED = 1;

    public const CLEAN = 2;

    /**
     * @param array<string, array<int, Shape|bool|null>> $properties each property read through `$this`, and
     *        each answer the run read from it: see {@see VALUE}
     * @param array<string, array{string, array<int, int|string>, string|null}> $calls each method called on
     *        `$this`, by call signature: its key, the literals it was called with, and the key of the
     *        summary the call applied, or null when the call applied one it was still waiting to replace
     * @param array<string, string|null> $allocations each `$this->name` whose object a call was made on,
     *        and the one allocation site it held, or null for none
     * @param bool $opaque the run reached `$this` through a copy, `$that = $this`, where a read or a
     *        call no longer says which object it is on
     * @param bool $writes the run wrote a property of `$this`, or of an object a property of `$this`
     *        holds, and the method's own run holds such writes back: see
     *        {@see IntraproceduralAnalyzer::holdsBackReceiverWrites()}
     */
    public function __construct(
        public readonly array $properties = [],
        public readonly array $calls = [],
        public readonly array $allocations = [],
        public readonly bool $opaque = false,
        public readonly bool $writes = false,
    ) {
    }

    /**
     * Whether the view can say anything about another receiver at all.
     */
    public function answersForOthers(): bool
    {
        return ! $this->opaque && ! $this->writes;
    }

    /**
     * This view with the write flag settled by the method's own run.
     */
    public function withWrites(bool $writes): self
    {
        return $writes === $this->writes
            ? $this
            : new self($this->properties, $this->calls, $this->allocations, $this->opaque, $writes);
    }

    /**
     * Whether a read of the property on another receiver gives each answer
     * this run read from it.
     *
     * @param array<int, Shape|bool|null> $seen every answer the read gives there
     */
    public function sawSame(string $property, array $seen): bool
    {
        $mine = $this->properties[$property] ?? null;

        if ($mine === null) {
            return false;
        }

        foreach ($mine as $answer => $value) {
            $there = $seen[$answer] ?? null;
            $same = $value instanceof Shape
                ? $there instanceof Shape && $value->equals($there)
                : array_key_exists($answer, $seen) && $there === $value;

            if (! $same) {
                return false;
            }
        }

        return true;
    }

    public function equals(?self $other): bool
    {
        if ($other === null) {
            return false;
        }

        if ($other === $this) {
            return true;
        }

        if (
            $this->opaque !== $other->opaque
            || $this->writes !== $other->writes
            || $this->calls !== $other->calls
            || $this->allocations !== $other->allocations
            || array_keys($this->properties) !== array_keys($other->properties)
        ) {
            return false;
        }

        foreach ($other->properties as $property => $seen) {
            $mine = $this->properties[$property] ?? [];

            if (array_keys($seen) !== array_keys($mine) || ! $this->sawSame($property, $seen)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Two bodies of one function key. Where they saw different things, no
     * single view answers for both, so the result answers for no other
     * receiver.
     */
    public function union(self $other): self
    {
        $opaque = $this->opaque || $other->opaque;
        $properties = $this->properties;

        foreach ($other->properties as $property => $seen) {
            if (isset($properties[$property]) && array_keys($properties[$property]) !== array_keys($seen)) {
                $opaque = true;
            } elseif (isset($properties[$property]) && ! $this->sawSame($property, $seen)) {
                $opaque = true;
            }

            $properties[$property] ??= $seen;
        }

        foreach ($other->calls as $signature => $call) {
            $opaque = $opaque || (isset($this->calls[$signature]) && $this->calls[$signature] !== $call);
        }

        foreach ($other->allocations as $property => $site) {
            $opaque = $opaque
                || (array_key_exists($property, $this->allocations) && $this->allocations[$property] !== $site);
        }

        ksort($properties);
        $calls = $this->calls + $other->calls;
        ksort($calls);
        $allocations = $this->allocations + $other->allocations;
        ksort($allocations);

        return new self($properties, $calls, $allocations, $opaque, $this->writes || $other->writes);
    }
}
