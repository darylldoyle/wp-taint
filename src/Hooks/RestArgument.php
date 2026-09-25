<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Hooks;

use Enshrined\WpTaint\Taint\CallTarget;

/**
 * One entry of a route's `args` schema: what WordPress does to that parameter
 * before the route's callback sees it.
 *
 * `WP_REST_Request::sanitize_params()` runs the argument's `sanitize_callback`
 * on the value and stores the result; with no `sanitize_callback` key and a
 * `type`, it runs `rest_parse_request_arg()`, which validates the value against
 * the schema (an `enum` refuses anything not listed) and then sanitises it by
 * type and format. An explicit empty `sanitize_callback` turns that default
 * off. See {@see \Enshrined\WpTaint\Taint\RestParameterSanitizer}.
 */
final class RestArgument
{
    /**
     * @param list<CallTarget>|null $sanitizers what the `sanitize_callback` resolved to; null when the key is
     *                                          absent, an empty list when it could not be resolved
     * @param bool                  $sanitizeDisabled `sanitize_callback` is present and empty, so no default runs
     * @param bool                  $readable whether the schema entry itself was a literal array
     */
    public function __construct(
        public readonly ?array $sanitizers,
        public readonly bool $sanitizeDisabled,
        public readonly ?string $type,
        public readonly ?string $format,
        public readonly bool $enum,
        public readonly bool $readable = true,
    ) {
    }

    /**
     * A parameter the schema says nothing readable about.
     */
    public static function unknown(): self
    {
        return new self(null, true, null, null, false, false);
    }
}
