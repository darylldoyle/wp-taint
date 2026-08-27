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

    public function __construct()
    {
        $this->byFunc = new SplObjectStorage();
    }

    public function addFile(ParsedFile $file): void
    {
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
