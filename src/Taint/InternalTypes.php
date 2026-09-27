<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use ReflectionClass;
use ReflectionFunction;
use ReflectionNamedType;
use ReflectionType;

/**
 * The class PHP's own functions and methods are declared to return.
 *
 * `ReflectionFunction::getClosureCalledClass()` is declared `?ReflectionClass`.
 * PHP's reflection says so, and it is the same kind of fact as a return type
 * written in the scanned code: a declaration, not an inference.
 *
 * Only a concrete class PHP itself defines is answered. An interface or an
 * abstract class names a family, not the object's class. A class the scanner
 * loaded for itself is not PHP's, even when a plugin bundles one of the same
 * name. A union such as `DateTime|false` names no one class.
 */
final class InternalTypes
{
    /** @var array<string, string|null> */
    private static array $methods = [];

    /** @var array<string, string|null> */
    private static array $functions = [];

    public static function methodReturnClass(string $class, string $method): ?string
    {
        $key = strtolower(ltrim($class, '\\') . '::' . $method);

        if (array_key_exists($key, self::$methods)) {
            return self::$methods[$key];
        }

        $owner = self::internalClass($class);

        if ($owner === null || ! $owner->hasMethod($method)) {
            return self::$methods[$key] = null;
        }

        $reflected = $owner->getMethod($method);

        return self::$methods[$key] = self::concreteClass(
            $reflected->getReturnType() ?? $reflected->getTentativeReturnType(),
            $owner,
        );
    }

    public static function functionReturnClass(string $function): ?string
    {
        $key = strtolower(ltrim($function, '\\'));

        if (array_key_exists($key, self::$functions)) {
            return self::$functions[$key];
        }

        if (! function_exists($key)) {
            return self::$functions[$key] = null;
        }

        $reflected = new ReflectionFunction($key);

        return self::$functions[$key] = $reflected->isInternal()
            ? self::concreteClass($reflected->getReturnType() ?? $reflected->getTentativeReturnType(), null)
            : null;
    }

    /**
     * @return ReflectionClass<object>|null
     */
    private static function internalClass(string $name): ?ReflectionClass
    {
        $name = ltrim($name, '\\');

        // Never autoload: the question is about what PHP defines, and asking
        // the autoloader could load the scanner's own copy of a class.
        if (! class_exists($name, false) && ! interface_exists($name, false)) {
            return null;
        }

        $class = new ReflectionClass($name);

        return $class->isInternal() ? $class : null;
    }

    /**
     * @param ReflectionClass<object>|null $self
     */
    private static function concreteClass(?ReflectionType $type, ?ReflectionClass $self): ?string
    {
        if (! $type instanceof ReflectionNamedType || $type->isBuiltin()) {
            return null;
        }

        $name = $type->getName();

        if ($self !== null && in_array(strtolower($name), ['self', 'static'], true)) {
            $name = $self->getName();
        }

        $class = self::internalClass($name);

        return $class === null || $class->isInterface() || $class->isAbstract() ? null : $class->getName();
    }
}
