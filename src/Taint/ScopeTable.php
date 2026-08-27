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
 * interprocedural loop.
 *
 * ## Two halves, deliberately
 *
 * **In** is what a file may find in a variable when it starts, unioned over
 * every site that includes it. **Out** is what the file's own top-level code
 * leaves behind, and only for names it actually assigns.
 *
 * Keeping them apart is not tidiness. With one entry per file, a variable
 * pushed *in* by one includer came straight back *out* to every other:
 * Jetpack's `constants.php` handed `$page_routes` — a name it never mentions —
 * to a function that merely required it, and twenty findings followed. The
 * conflation makes every shared partial a channel between unrelated callers.
 *
 * `in` is still unioned across includers, which is a real over-approximation and
 * the honest one: a template included from two places can see either caller's
 * state.
 *
 * Union only, so the loop terminates.
 */
final class ScopeTable
{
    /**
     * What each file may find in scope on entry.
     *
     * @var array<string, array<string, TaintSet>> file key => variable name => taint
     */
    private array $in = [];

    /**
     * What each file leaves behind, for names it assigns itself.
     *
     * @var array<string, array<string, TaintSet>> file key => variable name => taint
     */
    private array $out = [];

    /**
     * How many names to track per file.
     *
     * A `{main}` body with hundreds of locals is a procedural script, not a
     * template, and joining all of it to its includers costs more than it
     * explains.
     */
    private const MAX_NAMES = 128;

    /**
     * @return array<string, TaintSet>
     */
    public function scopeInto(string $key): array
    {
        return $this->in[$key] ?? [];
    }

    /**
     * @return array<string, TaintSet>
     */
    public function scopeOutOf(string $key): array
    {
        return $this->out[$key] ?? [];
    }

    /**
     * @param array<string, TaintSet> $scope
     */
    public function addInto(string $key, array $scope): bool
    {
        return self::merge($this->in, $key, $scope);
    }

    /**
     * @param array<string, TaintSet> $scope
     */
    public function addOutOf(string $key, array $scope): bool
    {
        return self::merge($this->out, $key, $scope);
    }

    /**
     * Fold another table into this one, for merging what each `--jobs` worker
     * recorded. A union, so the order cannot change the result.
     */
    public function mergeFrom(self $other): bool
    {
        $changed = false;

        foreach ($other->in as $key => $scope) {
            $changed = $this->addInto($key, $scope) || $changed;
        }

        foreach ($other->out as $key => $scope) {
            $changed = $this->addOutOf($key, $scope) || $changed;
        }

        return $changed;
    }

    public function count(): int
    {
        return count($this->in) + count($this->out);
    }

    /**
     * @param array<string, array<string, TaintSet>> $target
     * @param array<string, TaintSet>                $scope
     */
    private static function merge(array &$target, string $key, array $scope): bool
    {
        $changed = false;

        foreach ($scope as $name => $taint) {
            if ($taint->isEmpty()) {
                continue;
            }

            if (! isset($target[$key][$name]) && count($target[$key] ?? []) >= self::MAX_NAMES) {
                continue;
            }

            $existing = $target[$key][$name] ?? TaintSet::empty();
            $merged = $existing->union($taint);

            if ($merged->equals($existing)) {
                continue;
            }

            $target[$key][$name] = $merged;
            $changed = true;
        }

        return $changed;
    }
}
