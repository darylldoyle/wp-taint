<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\CallTarget;

/**
 * One route definition passed to `register_rest_route()`, resolved.
 *
 * A route that lists several definitions, one per method, is several of these.
 */
final class RestRoute
{
    /**
     * @param list<CallTarget>                 $callbacks  what `callback` resolved to
     * @param list<CallTarget>|null            $permission what `permission_callback` resolved to, or null
     *                                                     when the definition has none
     * @param array<string, RestArgument>|null $arguments  the `args` schema by parameter name, with the shared
     *                                                     `args` merged in as WordPress does, or null when it
     *                                                     could not be read
     */
    public function __construct(
        public readonly array $callbacks,
        public readonly ?array $permission,
        public readonly ?array $arguments,
        public readonly string $file,
        public readonly int $line,
    ) {
    }
}
