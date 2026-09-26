<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use ReflectionProperty;

/**
 * Takes a parsed file's graph apart, so reference counting frees it.
 *
 * A php-cfg graph is a web of cycles: an operand lists the ops that read and
 * write it, a block lists its ops and its parents, a function holds its entry
 * block and the op that declares it. A graph nothing points to any more is
 * still garbage only PHP's cycle collector can find, and on a large scan that
 * collector spent a quarter of its time looking. Emptying every array of
 * objects and every nullable object link leaves only the one-way links that
 * non-nullable typed properties hold, such as a jump's target, and those free
 * as soon as nothing outside points in.
 *
 * Every link that closes a cycle is a public property: php-cfg keeps its
 * graph in public fields. The walk reads every property, private and
 * protected ones too, by casting each object to an array, and clears only
 * the public ones. Reading by cast is several times faster than reading
 * through reflection; reflection is kept for the writes, which are far fewer,
 * and learned once per class.
 *
 * Only for a file nothing will read again. Every op and operand in it is left
 * hollow: an analysis still holding one would see a graph with no edges. See
 * {@see \Enshrined\WpTaint\Taint\FunctionBodies} for who may call this.
 */
final class GraphDisposer
{
    /**
     * Per class, its public properties that may be written, each with whether
     * it takes null. Readonly properties are left out.
     *
     * @var array<class-string, array<string, array{0: ReflectionProperty, 1: bool}>>
     */
    private static array $writable = [];

    public static function dispose(ParsedFile $file): void
    {
        $pending = [$file];
        $seen = [];

        /** @var list<object> $objects */
        $objects = [];

        // Collect first, then clear: clearing as we go would cut the walk off
        // from whatever lay behind an emptied array.
        while ($pending !== []) {
            $object = array_pop($pending);
            $id = spl_object_id($object);

            if (isset($seen[$id])) {
                continue;
            }

            $seen[$id] = true;
            $objects[] = $object;

            foreach ((array) $object as $value) {
                if (is_object($value)) {
                    $pending[] = $value;

                    continue;
                }

                if (! is_array($value)) {
                    continue;
                }

                foreach ($value as $inner) {
                    if (is_object($inner)) {
                        $pending[] = $inner;

                        continue;
                    }

                    // Phi vars and assertion lists nest one level deeper.
                    if (is_array($inner)) {
                        foreach ($inner as $deep) {
                            if (is_object($deep)) {
                                $pending[] = $deep;
                            }
                        }
                    }
                }
            }
        }

        foreach ($objects as $held) {
            $writable = self::$writable[$held::class] ?? self::learn($held::class);

            foreach ((array) $held as $name => $value) {
                // Private and protected properties arrive with a NUL-prefixed
                // name, and readonly ones are not listed. None of php-cfg's
                // cycles run through them.
                $property = $writable[$name] ?? null;

                if ($property === null) {
                    continue;
                }

                if (is_array($value)) {
                    if ($value !== []) {
                        $property[0]->setValue($held, []);
                    }

                    continue;
                }

                if (is_object($value) && $property[1]) {
                    $property[0]->setValue($held, null);
                }
            }
        }
    }

    /**
     * @param class-string $class
     *
     * @return array<string, array{0: ReflectionProperty, 1: bool}>
     */
    private static function learn(string $class): array
    {
        $properties = [];

        foreach ((new \ReflectionClass($class))->getProperties(ReflectionProperty::IS_PUBLIC) as $property) {
            if ($property->isStatic() || $property->isReadOnly()) {
                continue;
            }

            $type = $property->getType();
            $properties[$property->getName()] = [$property, $type === null || $type->allowsNull()];
        }

        return self::$writable[$class] = $properties;
    }
}
