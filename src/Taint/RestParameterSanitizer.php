<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Hooks\RestArgument;
use Enshrined\WpTaint\Hooks\RestRoute;
use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Registry;

/**
 * What a REST parameter carries by the time the route's callback reads it.
 *
 * `WP_REST_Request::sanitize_params()` runs before the callback, so
 * `$request['id']` in a route declared with `'id' => [ 'sanitize_callback' =>
 * 'absint' ]` is already an integer. Crediting that is sound where crediting a
 * filter callback is not: the schema is fixed where the route is registered,
 * and nothing can take it off again at runtime.
 *
 * Core's order, for one schema entry:
 *
 * - A `sanitize_callback` runs on the value: a catalogue sanitizer by its
 *   catalogue entry, a function of the scan's by its summary, anything else
 *   as clearing nothing.
 * - An empty `sanitize_callback` runs nothing.
 * - No `sanitize_callback` key and a `type`: `rest_parse_request_arg()`, which
 *   validates against the schema, so an `enum` refuses any value not listed,
 *   then casts `integer`, `number` and `boolean`, and runs a `format` through
 *   its sanitizer.
 *
 * A callback handling several routes gets the union across them, and a route
 * whose schema could not be read sanitises nothing, so the answer never
 * credits a sanitizer that some route to the callback does not run.
 */
final class RestParameterSanitizer
{
    /** `rest_sanitize_value_from_schema()`'s `format` cases, for a string. */
    private const FORMATS = [
        'hex-color' => 'sanitize_hex_color',
        'date-time' => 'sanitize_text_field',
        'email' => 'sanitize_text_field',
        'uri' => 'sanitize_url',
        'ip' => 'sanitize_text_field',
        'uuid' => 'sanitize_text_field',
        'text-field' => 'sanitize_text_field',
        'textarea-field' => 'sanitize_textarea_field',
    ];

    /** Functions that sanitise a parameter by its own schema. */
    private const SCHEMA_SANITIZERS = ['rest_parse_request_arg', 'rest_sanitize_request_arg'];

    public function __construct(
        private readonly Registry $registry,
        private readonly SummaryTable $summaries,
    ) {
    }

    /**
     * @param list<RestRoute> $routes the routes the reading callback handles
     */
    public function sanitize(TaintSet $kinds, string $parameter, array $routes): TaintSet
    {
        if ($routes === []) {
            return $kinds;
        }

        $result = TaintSet::empty();

        foreach ($routes as $route) {
            $argument = $route->arguments === null ? null : ($route->arguments[$parameter] ?? null);
            $result = $result->union($argument === null ? $kinds : $this->forArgument($kinds, $argument));
        }

        return $result;
    }

    private function forArgument(TaintSet $kinds, RestArgument $argument): TaintSet
    {
        if (! $argument->readable || $argument->sanitizeDisabled) {
            return $kinds;
        }

        if ($argument->sanitizers === null) {
            return $argument->type === null ? $kinds : $this->bySchema($kinds, $argument, validates: true);
        }

        if ($argument->sanitizers === []) {
            return $kinds;
        }

        $result = TaintSet::empty();

        foreach ($argument->sanitizers as $sanitizer) {
            $result = $result->union($this->byCallback($kinds, $argument, $sanitizer));
        }

        return $result;
    }

    private function byCallback(TaintSet $kinds, RestArgument $argument, CallTarget $callback): TaintSet
    {
        if ($callback->dynamic) {
            return $kinds;
        }

        $matcher = $callback->matcher;

        if ($matcher !== null) {
            $name = strtolower($matcher->name);

            if ($callback->userFunctionKey === null && in_array($name, self::SCHEMA_SANITIZERS, true)) {
                return $this->bySchema($kinds, $argument, validates: $name === 'rest_parse_request_arg');
            }

            $sanitizer = $this->registry->sanitizer($matcher);

            if ($sanitizer !== null && $callback->userFunctionKey === null) {
                // A strategy needs the call's own arguments to say what it
                // clears, and WordPress passes it the value, the request and the
                // key. Credited as clearing nothing rather than guessed at.
                return $sanitizer->clearsBy === null ? $sanitizer->transform($kinds) : $kinds;
            }
        }

        if ($callback->userFunctionKey === null) {
            return $kinds;
        }

        // The callback's own summary, read through the table, so the fixed
        // point revisits this read when that summary changes.
        $summary = $this->summaries->get($callback->userFunctionKey);

        if ($summary === null) {
            return $kinds;
        }

        return $kinds->intersect($summary->returnTaintFor(0))->union($summary->introduces());
    }

    /**
     * `rest_parse_request_arg()`, or `rest_sanitize_request_arg()` without the
     * validation.
     */
    private function bySchema(TaintSet $kinds, RestArgument $argument, bool $validates): TaintSet
    {
        $objectId = $kinds->intersect(TaintSet::of(TaintKind::ObjectId));

        // A value that fails validation never reaches the callback. One that
        // passes an `enum` is one of the values the route listed, which carries
        // no payload, though it can still name somebody else's row.
        if ($validates && $argument->enum) {
            return $objectId;
        }

        return match ($argument->type) {
            'integer', 'number' => $objectId,
            'boolean', 'null' => TaintSet::empty(),
            // Core applies a format to a string, or to a value with no type.
            'string', null => $argument->format !== null && isset(self::FORMATS[$argument->format])
                ? $this->byFunction($kinds, self::FORMATS[$argument->format])
                : $kinds,
            default => $kinds,
        };
    }

    private function byFunction(TaintSet $kinds, string $function): TaintSet
    {
        $sanitizer = $this->registry->sanitizer(Matcher::function($function));

        return $sanitizer === null || $sanitizer->clearsBy !== null ? $kinds : $sanitizer->transform($kinds);
    }
}
