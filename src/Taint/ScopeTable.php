<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\TraceStep;

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
     * The trace of the assignment that put taint into each variable.
     *
     * A finding that enters through an include used to begin "$title was in
     * scope at the include that loaded this file" and stop there — a dead end
     * that tells a reviewer nothing about whether the value is attacker
     * controlled. The property map solved the identical problem by recording
     * the write's trace and splicing it in ahead of the read.
     *
     * @var array<string, array<string, list<TraceStep>>>
     */
    private array $origins = [];

    /**
     * Per-key taint for a variable that crosses the boundary as an array.
     *
     * `get_template_part( 'card', null, [ 'title' => $_GET['t'], 'id' => 7 ] )`
     * hands the template an array whose keys are separately tainted, and the
     * template reading `$args['id']` should be no more a finding than reading
     * `$context['id']` in the file that built it.
     *
     * @var array<string, array<string, array<string, TaintSet>>> file => name => key => taint
     */
    private array $keyed = [];

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
     * @param array<string, TaintSet>                     $scope
     * @param array<string, list<TraceStep>>               $origins
     * @param array<string, array<string, TaintSet>>       $keyed
     */
    public function addInto(string $key, array $scope, array $origins = [], array $keyed = []): bool
    {
        $this->recordOrigins($key, $origins);
        $this->recordKeyed($key, $keyed);

        return self::merge($this->in, $key, $scope);
    }

    /**
     * @return array<string, array<string, TaintSet>>
     */
    public function keyedInto(string $key): array
    {
        return $this->keyed[$key] ?? [];
    }

    /**
     * @param array<string, array<string, TaintSet>> $keyed
     */
    private function recordKeyed(string $key, array $keyed): void
    {
        foreach ($keyed as $name => $keys) {
            foreach ($keys as $index => $taint) {
                $existing = $this->keyed[$key][$name][$index] ?? TaintSet::empty();
                $this->keyed[$key][$name][$index] = $existing->union($taint);
            }
        }
    }

    /**
     * @param array<string, TaintSet>        $scope
     * @param array<string, list<TraceStep>> $origins
     */
    public function addOutOf(string $key, array $scope, array $origins = []): bool
    {
        $this->recordOrigins($key, $origins);

        return self::merge($this->out, $key, $scope);
    }

    /**
     * The trace of the write that tainted a variable, for splicing ahead of the
     * step that reads it.
     *
     * @return list<TraceStep>
     */
    public function originOf(string $key, string $name): array
    {
        return $this->origins[$key][$name] ?? [];
    }

    /**
     * @param array<string, list<TraceStep>> $origins
     */
    private function recordOrigins(string $key, array $origins): void
    {
        foreach ($origins as $name => $origin) {
            if ($origin === []) {
                continue;
            }

            $current = $this->origins[$key][$name] ?? [];

            // Smallest signature, exactly as the property map does it, and for
            // the same reason: "longest wins" does not terminate when a value
            // flows through a cycle, and an include chain can be one.
            if ($current === [] || self::signature($origin) < self::signature($current)) {
                $this->origins[$key][$name] = $origin;
            }
        }
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

        foreach ($other->origins as $key => $origins) {
            $this->recordOrigins($key, $origins);
        }

        foreach ($other->keyed as $key => $keyed) {
            $this->recordKeyed($key, $keyed);
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
