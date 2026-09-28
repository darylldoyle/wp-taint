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
     * What each file may find in scope on entry: each variable as a shape,
     * its own taint on top and its elements below, so a template reading
     * `$args['id']` sees only what `'id'` held.
     *
     * @var array<string, array<string, Shape>> file key => variable name => value
     */
    private array $in = [];

    /**
     * What each file leaves behind, for names it assigns itself.
     *
     * @var array<string, array<string, Shape>> file key => variable name => value
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
     * How many names to track per file.
     *
     * A `{main}` body with hundreds of locals is a procedural script, not a
     * template, and joining all of it to its includers costs more than it
     * explains.
     */
    private const MAX_NAMES = 128;

    private ?ReadLog $log = null;

    /**
     * Record every read from now on. See {@see ReadLog}.
     */
    public function recordReadsInto(?ReadLog $log): void
    {
        $this->log = $log;
    }

    /**
     * @return array<string, Shape>
     */
    public function scopeInto(string $key): array
    {
        $this->log?->record('si:' . $key);

        return $this->in[$key] ?? [];
    }

    /**
     * @return array<string, Shape>
     */
    public function scopeOutOf(string $key): array
    {
        $this->log?->record('so:' . $key);

        return $this->out[$key] ?? [];
    }

    /**
     * @param array<string, Shape>           $scope
     * @param array<string, list<TraceStep>> $origins
     */
    public function addInto(string $key, array $scope, array $origins = []): bool
    {
        $this->recordOrigins($key, $origins);

        return self::merge($this->in, $key, self::forOtherRuns($scope));
    }

    /**
     * A scope as another run reads it: no element numbers, see
     * TaintSet::withoutElements(), and no write, which belongs to the graph
     * the run that published it analysed.
     *
     * @param array<string, Shape> $scope
     *
     * @return array<string, Shape>
     */
    private static function forOtherRuns(array $scope): array
    {
        return array_map(
            static fn (Shape $value): Shape => $value->mapSets(
                static fn (TaintSet $taint): TaintSet => $taint->withoutElements(),
            ),
            $scope,
        );
    }

    /**
     * @param array<string, Shape>           $scope
     * @param array<string, list<TraceStep>> $origins
     */
    public function addOutOf(string $key, array $scope, array $origins = []): bool
    {
        $this->recordOrigins($key, $origins);

        return self::merge($this->out, $key, self::forOtherRuns($scope));
    }

    /**
     * The trace of the write that tainted a variable, for splicing ahead of the
     * step that reads it.
     *
     * @return list<TraceStep>
     */
    public function originOf(string $key, string $name): array
    {
        $this->log?->record('sg:' . $key);

        return $this->origins[$key][$name] ?? [];
    }

    /**
     * @param array<string, list<TraceStep>> $origins
     */
    private function recordOrigins(string $key, array $origins): bool
    {
        $changed = false;

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
                $changed = true;
            }
        }

        return $changed;
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
        return $this->mergeChanges($other)['changed'];
    }

    /**
     * Merge, and say which entries moved.
     *
     * `changed` is what it always was: whether a scope's variables grew, which
     * is what keeps the fixed point going. Origins never counted towards
     * that, and still do not. They are in `entries` all the same, as
     * {@see ReadLog} keys, because a function that read one reads something
     * different now.
     *
     * @return array{changed: bool, entries: list<string>}
     */
    public function mergeChanges(self $other): array
    {
        $changed = false;
        $entries = [];

        foreach ($other->in as $key => $scope) {
            if (self::merge($this->in, $key, $scope)) {
                $changed = true;
                $entries['si:' . $key] = true;
            }
        }

        foreach ($other->out as $key => $scope) {
            if (self::merge($this->out, $key, $scope)) {
                $changed = true;
                $entries['so:' . $key] = true;
            }
        }

        foreach ($other->origins as $key => $origins) {
            if ($this->recordOrigins($key, $origins)) {
                $entries['sg:' . $key] = true;
            }
        }

        return ['changed' => $changed, 'entries' => array_keys($entries)];
    }

    public function count(): int
    {
        return count($this->in) + count($this->out);
    }

    /**
     * @param array<string, array<string, Shape>> $target
     * @param array<string, Shape>                $scope
     */
    private static function merge(array &$target, string $key, array $scope): bool
    {
        $changed = false;

        foreach ($scope as $name => $value) {
            if ($value->isEmpty()) {
                continue;
            }

            if (! isset($target[$key][$name]) && count($target[$key] ?? []) >= self::MAX_NAMES) {
                continue;
            }

            $existing = $target[$key][$name] ?? Shape::empty();
            $merged = $existing->join($value);

            // A join that adds nothing hands back the shape it joined into.
            if ($merged === $existing) {
                continue;
            }

            $target[$key][$name] = $merged;
            $changed = true;
        }

        return $changed;
    }
}
