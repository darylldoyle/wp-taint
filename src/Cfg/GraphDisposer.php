<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use ReflectionClass;
use ReflectionNamedType;
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
 * Only for a file nothing will read again. Every op and operand in it is left
 * hollow: an analysis still holding one would see a graph with no edges. See
 * {@see \Enshrined\WpTaint\Taint\FunctionBodies} for who may call this.
 */
final class GraphDisposer
{
    /** @var array<class-string, list<ReflectionProperty>> the properties that can hold objects, by class */
    private static array $linking = [];

    public static function dispose(ParsedFile $file): void
    {
        $pending = [$file];
        $seen = [];
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

            foreach (self::linking($object) as $property) {
                if (! $property->isInitialized($object)) {
                    continue;
                }

                $value = $property->getValue($object);

                foreach (is_array($value) ? $value : [$value] as $inner) {
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
            foreach (self::linking($held) as $property) {
                if ($property->isReadOnly() || ! $property->isInitialized($held)) {
                    continue;
                }

                $value = $property->getValue($held);

                if (is_array($value)) {
                    if ($value !== []) {
                        $property->setValue($held, []);
                    }

                    continue;
                }

                if (is_object($value) && self::nullable($property)) {
                    $property->setValue($held, null);
                }
            }
        }
    }

    /**
     * The instance properties of a php-cfg object that can hold other objects.
     * Readonly ones are walked, since what lies behind them may close a cycle,
     * and never written.
     *
     * @return list<ReflectionProperty>
     */
    private static function linking(object $object): array
    {
        $class = $object::class;

        if (isset(self::$linking[$class])) {
            return self::$linking[$class];
        }

        $properties = [];

        foreach ((new ReflectionClass($class))->getProperties() as $property) {
            if ($property->isStatic()) {
                continue;
            }

            $type = $property->getType();

            // Scalars never close a cycle.
            $scalar = $type instanceof ReflectionNamedType
                && $type->isBuiltin()
                && ! in_array($type->getName(), ['array', 'mixed', 'object'], true);

            if ($scalar) {
                continue;
            }

            $properties[] = $property;
        }

        return self::$linking[$class] = $properties;
    }

    private static function nullable(ReflectionProperty $property): bool
    {
        $type = $property->getType();

        return $type === null || $type->allowsNull();
    }
}
