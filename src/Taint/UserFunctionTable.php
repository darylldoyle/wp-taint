<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use PHPCfg\Func;
use SplObjectStorage;

/**
 * Every function, method and closure in the scanned code, indexed for call
 * resolution.
 *
 * Interprocedural analysis crosses files, so this is built once for the whole
 * scan rather than per file.
 */
final class UserFunctionTable
{
    /** @var array<string, FunctionContext> */
    private array $byKey = [];

    /** @var array<string, list<FunctionContext>> */
    private array $byMethodName = [];

    /** @var array<string, true> */
    private array $definedMethodNames = [];

    /** @var list<FunctionContext> */
    private array $all = [];

    /** @var SplObjectStorage<Func, FunctionContext> */
    private SplObjectStorage $byFunc;

    private DeclaredTypes $declared;

    private ClassHierarchy $hierarchy;

    public function __construct()
    {
        $this->byFunc = new SplObjectStorage();
        $this->declared = new DeclaredTypes();
        $this->hierarchy = new ClassHierarchy();
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
        $this->add(FunctionContext::create($file->script->main, $file));

        foreach ($file->script->functions as $func) {
            if (! $func instanceof Func) {
                continue;
            }

            $this->add(FunctionContext::create($func, $file));
        }
    }

    private function add(FunctionContext $context): void
    {
        // A duplicate key means the same function is declared twice across the
        // scanned tree — a conditionally-defined shim, or a vendored copy. The
        // first declaration wins, deterministically, because files are walked
        // in sorted order.
        $this->byKey[$context->key] ??= $context;
        $this->declared->observeFunction($context);
        $this->all[] = $context;
        $this->byFunc[$context->func] = $context;

        if ($context->className === null) {
            return;
        }

        $method = strtolower($context->func->name);
        $this->byMethodName[$method][] = $context;
        $this->definedMethodNames[$method] = true;
    }

    /**
     * The context for a `Func` we already hold, used to resolve a closure back
     * to its summary key once the closure operand has been traced to its
     * declaration.
     */
    public function forFunc(Func $func): ?FunctionContext
    {
        return $this->byFunc->contains($func) ? $this->byFunc[$func] : null;
    }

    public function get(string $key): ?FunctionContext
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
     * The single method with this name, when the codebase declares exactly one.
     */
    public function uniqueMethodNamed(string $method): ?FunctionContext
    {
        $candidates = $this->byMethodName[strtolower($method)] ?? [];

        return count($candidates) === 1 ? $candidates[0] : null;
    }

    /**
     * @return list<FunctionContext>
     */
    public function all(): array
    {
        return $this->all;
    }
}
