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
}
