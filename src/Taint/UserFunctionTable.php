<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use PHPCfg\Func;

/**
 * Every function, method and closure in the scanned code, indexed for call
 * resolution.
 *
 * Interprocedural analysis crosses files, so this is built once for the whole
 * scan rather than per file. It holds each function's {@see FunctionMeta}, not
 * its body: nothing here keeps a control flow graph alive. A body comes from
 * {@see FunctionBodies}.
 */
final class UserFunctionTable
{
    /** @var array<string, FunctionMeta> */
    private array $byKey = [];

    /** @var array<string, list<FunctionMeta>> */
    private array $byMethodName = [];

    /** @var array<string, list<FunctionMeta>> lowercased class => its own methods */
    private array $byClass = [];

    /** @var array<string, true> */
    private array $definedMethodNames = [];

    /** @var list<FunctionMeta> */
    private array $all = [];

    /** @var array<string, string> class and method => receiver key, see receiverOf() */
    private array $receivers = [];

    /** @var array<string, array{list<string>, array<string, true>}> receiver key => see classSlotsOf() */
    private array $classSlots = [];

    /** @var array<string, array<string, true>> class => see relatedClasses() */
    private array $related = [];

    /** Which methods call which, once the scan has built it: see {@see useCallGraph()}. */
    private ?CallGraph $callGraph = null;

    private DeclaredTypes $declared;

    private ClassHierarchy $hierarchy;

    public function __construct()
    {
        $this->hierarchy = new ClassHierarchy();
        $this->declared = new DeclaredTypes($this->hierarchy);
    }

    /**
     * What the scanned code declares about its own types.
     *
     * Built here because this is the one place that already walks every
     * function of every file, and because it has to happen while the AST is
     * still held.
     */
    public function declaredTypes(): DeclaredTypes
    {
        return $this->declared;
    }

    /**
     * Who extends whom, and who uses which trait — built here for the same
     * reason {@see declaredTypes} is: this is the one walk that holds every
     * file's AST.
     */
    public function classHierarchy(): ClassHierarchy
    {
        return $this->hierarchy;
    }

    public function addFile(ParsedFile $file): void
    {
        $this->declared->observeFile($file);
        $this->hierarchy->observeFile($file);
        $this->add(FunctionContext::create($file->script->main, $file), null);

        foreach (array_values($file->script->functions) as $position => $func) {
            if (! $func instanceof Func) {
                continue;
            }

            $this->add(FunctionContext::create($func, $file), $position);
        }
    }

    private function add(FunctionContext $context, ?int $position): void
    {
        $meta = FunctionMeta::of($context, $position);

        // A duplicate key means the same function is declared twice across the
        // scanned tree — a conditionally-defined shim, or a vendored copy. The
        // first declaration wins, deterministically, because files are walked
        // in sorted order.
        $this->byKey[$meta->key] ??= $meta;
        $this->declared->observeFunction($context);
        $this->all[] = $meta;

        if ($meta->className === null) {
            return;
        }

        $this->byClass[strtolower(ltrim($meta->className, '\\'))][] = $meta;

        $method = strtolower($meta->name);
        $this->byMethodName[$method][] = $meta;
        $this->definedMethodNames[$method] = true;
    }

    public function get(string $key): ?FunctionMeta
    {
        return $this->byKey[strtolower($key)] ?? null;
    }

    public function has(string $key): bool
    {
        return isset($this->byKey[strtolower($key)]);
    }

    /**
     * The key of the body a method call on `$class` actually runs, following
     * PHP's own lookup: the class, its traits, then up the `extends` chain.
     *
     * `Acme_Child::table_name()` resolves to `acme_parent::table_name` when the
     * child declares nothing and the parent holds the body. Flat lookup
     * answered null there, which made every inherited helper a call the engine
     * could not see into. Null still means unresolved: a parent outside the
     * scan ends the walk rather than being guessed at.
     */
    public function resolveMethodKey(string $class, string $method): ?string
    {
        $method = strtolower($method);

        // The overwhelmingly common case — the class declares the method
        // itself — without building the linearization. This runs once per
        // call op per analysis round.
        $direct = strtolower(ltrim($class, '\\')) . '::' . $method;

        if (isset($this->byKey[$direct])) {
            return $direct;
        }

        foreach ($this->hierarchy->lookupOrder($class) as $candidate) {
            $key = $candidate . '::' . $method;

            if (isset($this->byKey[$key])) {
                return $key;
            }
        }

        return null;
    }

    /**
     * True when the scanned code declares a method with this name on any class.
     *
     * Used to decide whether it is safe to fall back to matching a registry
     * method entry on name alone when the receiver type is unknown. If the
     * codebase defines its own `query()`, guessing `wpdb::query()` would be a
     * false positive, so the fallback is withheld.
     */
    public function definesMethodNamed(string $method): bool
    {
        return isset($this->definedMethodNames[strtolower($method)]);
    }

    /**
     * Every method a class has, its own and those it inherits, in PHP's
     * lookup order.
     *
     * @return list<FunctionMeta>
     */
    public function methodsOf(string $class): array
    {
        $methods = [];

        foreach ($this->hierarchy->lookupOrder($class) as $candidate) {
            foreach ($this->byClass[$candidate] ?? [] as $context) {
                $methods[] = $context;
            }
        }

        return $methods;
    }

    /**
     * Every method with this name, on any class.
     *
     * @return list<FunctionMeta>
     */
    public function methodsNamed(string $method): array
    {
        return $this->byMethodName[strtolower($method)] ?? [];
    }

    /**
     * The single method with this name, when the codebase declares exactly one.
     */
    public function uniqueMethodNamed(string $method): ?FunctionMeta
    {
        $candidates = $this->byMethodName[strtolower($method)] ?? [];

        return count($candidates) === 1 ? $candidates[0] : null;
    }

    /**
     * @return list<FunctionMeta>
     */
    public function all(): array
    {
        return $this->all;
    }

    /**
     * Let {@see receiverOf()} see which descendants call a method they
     * override. The call graph is built after this table, from it.
     */
    public function useCallGraph(CallGraph $callGraph): void
    {
        $this->callGraph = $callGraph;
        $this->receivers = [];
        $this->classSlots = [];
    }

    /**
     * The objects a method runs on, as a receiver key: its class, which
     * stands for every object of it or of a descendant, or `class#method`
     * when a descendant declares its own method of that name and so never
     * runs this one.
     *
     * ```php
     * class Coupons_Store extends Data_Store { function get_data() { ... } }
     * class Coupons_Stats extends Coupons_Store { function get_data() { ... } }
     * ```
     *
     * `Coupons_Store::get_data()` never runs on a `Coupons_Stats` object, so
     * the LIMIT that object's own `get_data()` writes is not one it reads.
     * A descendant whose own methods call it, as `parent::get_data()` does,
     * runs it on its objects, so the key still stands for that descendant.
     *
     * Kept per class and method. The answer walks every descendant, and the
     * analysis asks it for every method call in every run: 1.3 million times
     * on Elementor.
     */
    public function receiverOf(string $class, string $method): string
    {
        $key = $class . '::' . $method;

        if (isset($this->receivers[$key])) {
            return $this->receivers[$key];
        }

        $declared = $this->resolveMethodKey($class, $method);

        foreach ($this->hierarchy->descendantsOf($class) as $descendant) {
            if (! $this->runsOn($descendant, $class, $method, $declared)) {
                return $this->receivers[$key] = strtolower(ltrim($class, '\\')) . '#' . strtolower($method);
            }
        }

        return $this->receivers[$key] = strtolower(ltrim($class, '\\'));
    }

    /**
     * Whether `$declared`, the body a call of `$method` on `$class` runs,
     * can run on an object of `$descendant`: the descendant inherits it, or
     * a method the descendant declares below `$class` calls it.
     */
    private function runsOn(string $descendant, string $class, string $method, ?string $declared): bool
    {
        if ($this->resolveMethodKey($descendant, $method) === $declared) {
            return true;
        }

        if ($declared === null || $this->callGraph === null) {
            return false;
        }

        $above = array_flip($this->hierarchy->lookupOrder($class));

        foreach ($this->hierarchy->lookupOrder($descendant) as $candidate) {
            if (isset($above[$candidate])) {
                continue;
            }

            foreach ($this->byClass[$candidate] ?? [] as $meta) {
                if (in_array($declared, $this->callGraph->calleesOf($meta->key), true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The class slots a read through a receiver key sees, and the classes
     * whose allocation sites it sees too.
     *
     * A class key stands for any object of it or of a descendant: the slots
     * of those classes and of its ancestors. A `class#method` key leaves out
     * the descendants that declare their own method of that name and never
     * call this one, as {@see receiverOf()} does. Kept per key, since it
     * depends only on the class hierarchy, the method table and the call
     * graph.
     *
     * @return array{list<string>, array<string, true>} the slots, and the lower-case classes whose
     *                                                   allocation sites the read also sees
     */
    public function classSlotsOf(string $owner): array
    {
        if (isset($this->classSlots[$owner])) {
            return $this->classSlots[$owner];
        }

        $class = $owner;
        $method = null;
        $at = strpos($owner, '#');

        if ($at !== false) {
            $method = substr($owner, $at + 1);
            $class = substr($owner, 0, $at);
        }

        $slots = $this->hierarchy->lookupOrder($class);
        $below = [];
        $declared = $method === null ? null : $this->resolveMethodKey($class, $method);

        foreach ($this->hierarchy->descendantsOf($class) as $descendant) {
            if ($method !== null && ! $this->runsOn($descendant, $class, $method, $declared)) {
                continue;
            }

            $slots[] = $descendant;
            $below[strtolower($descendant)] = true;
        }

        $below[strtolower($class)] = true;

        return $this->classSlots[$owner] = [$slots, $below];
    }

    /**
     * A class, the classes and traits it inherits from, and every descendant
     * with theirs: the classes whose methods can run on an object of it.
     *
     * @return array<string, true> lower-case names
     */
    public function relatedClasses(string $class): array
    {
        if (isset($this->related[$class])) {
            return $this->related[$class];
        }

        $related = [];

        foreach ([$class, ...$this->hierarchy->descendantsOf($class)] as $each) {
            foreach ($this->hierarchy->lookupOrder($each) as $inherited) {
                $related[strtolower($inherited)] = true;
            }
        }

        return $this->related[$class] = $related;
    }
}
