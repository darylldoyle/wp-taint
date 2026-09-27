<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

/**
 * Every REST route the scan registers, by the function that handles it.
 *
 * A callback registered on several routes answers to all of them, so every
 * question asked of it is asked of each route and the least favourable answer
 * wins: entitled only if every route's permission callback entitles, and a
 * parameter sanitised only as far as every route sanitises it.
 */
final class RestRouteTable
{
    /** @var array<string, list<RestRoute>> callback function key => routes it handles */
    private array $byCallback = [];

    /** @var array<string, true> callback keys every one of whose routes has an entitling permission callback */
    private array $entitled = [];

    /** @var list<array{file: string, line: int, reason: string}> */
    private array $unresolved = [];

    /**
     * Per route, by object id, the request parameters its permission
     * callback admits only from a fixed list.
     *
     * @var array<int, array<string, true>>
     */
    private array $admitted = [];

    public function add(RestRoute $route): void
    {
        foreach ($route->callbacks as $callback) {
            if ($callback->userFunctionKey !== null) {
                $this->byCallback[$callback->userFunctionKey][] = $route;
            }
        }
    }

    public function recordUnresolved(string $file, int $line, string $reason): void
    {
        $this->unresolved[] = ['file' => $file, 'line' => $line, 'reason' => $reason];
    }

    /**
     * @return list<RestRoute>
     */
    public function routesFor(string $callbackKey): array
    {
        return $this->byCallback[strtolower($callbackKey)] ?? [];
    }

    public function handles(string $callbackKey): bool
    {
        return isset($this->byCallback[strtolower($callbackKey)]);
    }

    /**
     * @return list<string>
     */
    public function callbackKeys(): array
    {
        return array_keys($this->byCallback);
    }

    public function markEntitled(string $callbackKey): void
    {
        $this->entitled[strtolower($callbackKey)] = true;
    }

    /**
     * Whether WordPress only runs this callback for a caller its routes'
     * permission callbacks have entitled.
     */
    public function isEntitled(string $callbackKey): bool
    {
        return isset($this->entitled[strtolower($callbackKey)]);
    }

    /**
     * Record the parameters a route's permission callback admits only from a
     * fixed list. See {@see \Enshrined\WpTaint\Taint\PermissionAllowlist}.
     *
     * @param array<string, true> $parameters
     */
    public function admitFromList(RestRoute $route, array $parameters): void
    {
        $this->admitted[spl_object_id($route)] = $parameters;
    }

    /**
     * Whether every one of these routes lets a request through only when this
     * parameter is one of a fixed list.
     *
     * @param list<RestRoute> $routes
     */
    public function admitsOnlyFromList(array $routes, string $parameter): bool
    {
        foreach ($routes as $route) {
            if (! isset($this->admitted[spl_object_id($route)][$parameter])) {
                return false;
            }
        }

        return $routes !== [];
    }

    /**
     * @return list<array{file: string, line: int, reason: string}>
     */
    public function unresolved(): array
    {
        return $this->unresolved;
    }
}
