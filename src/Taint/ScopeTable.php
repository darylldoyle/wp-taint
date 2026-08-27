<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Variables in scope at the top level of each file, by name.
 *
 * PHP includes share the includer's variable scope, which is the whole reason
 * the theme shape works:
 *
 * ```php
 * $title = $_GET['title'];
 * include 'template.php';       // template.php echoes $title
 * ```
 *
 * Nothing in the call machinery models that. A call has positional parameters
 * and a return value; an include has *the caller's entire scope*, in both
 * directions, keyed by name.
 *
 * So this table sits alongside {@see PropertyTaintMap} and converges in the same
 * interprocedural loop. Each entry is what a file's `{main}` body may find in a
 * variable when it starts, unioned over every site that includes it — an
 * over-approximation, and the honest one: a template included from two places
 * really can see either caller's state.
 *
 * Union only, so the loop terminates.
 */
final class ScopeTable
{
    /**
     * @var array<string, array<string, TaintSet>> file key => variable name => taint
     */
    private array $scopes = [];

    /**
     * How many names to track per file.
     *
     * A `{main}` body with hundreds of locals is a procedural script, not a
     * template, and joining all of it to its includers costs more than it
     * explains.
     */
    private const MAX_NAMES = 128;

    public function taintOf(string $key, string $name): TaintSet
    {
        return $this->scopes[$key][$name] ?? TaintSet::empty();
    }

    /**
     * @return array<string, TaintSet>
     */
    public function scopeOf(string $key): array
    {
        return $this->scopes[$key] ?? [];
    }

    public function add(string $key, string $name, TaintSet $taint): bool
    {
        if ($taint->isEmpty()) {
            return false;
        }

        if (! isset($this->scopes[$key][$name]) && count($this->scopes[$key] ?? []) >= self::MAX_NAMES) {
            return false;
        }

        $existing = $this->scopes[$key][$name] ?? TaintSet::empty();
        $merged = $existing->union($taint);

        if ($merged->equals($existing)) {
            return false;
        }

        $this->scopes[$key][$name] = $merged;

        return true;
    }

    /**
     * @param array<string, TaintSet> $scope
     */
    public function addAll(string $key, array $scope): bool
    {
        $changed = false;

        foreach ($scope as $name => $taint) {
            $changed = $this->add($key, $name, $taint) || $changed;
        }

        return $changed;
    }

    /**
     * Fold another table into this one, for merging what each `--jobs` worker
     * recorded. A union, so the order cannot change the result.
     */
    public function mergeFrom(self $other): bool
    {
        $changed = false;

        foreach ($other->scopes as $key => $scope) {
            $changed = $this->addAll($key, $scope) || $changed;
        }

        return $changed;
    }

    public function count(): int
    {
        return count($this->scopes);
    }
}
