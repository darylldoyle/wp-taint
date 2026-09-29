<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * The parts a function reads each parameter through, so a probe can seed them
 * apart: see {@see TaintSet::fromPart()}.
 *
 * ```php
 * function acme_fields( $options ) {
 *     foreach ( $options as $field ) {
 *         echo '<input value="' . esc_attr( $field['value'] ) . '">';
 *         echo $field['desc'];
 *     }
 * }
 * ```
 *
 * reads `$options` through `[*]['value']` and `[*]['desc']`. Seeded apart, the
 * summary says only `desc` reaches the raw echo. A caller that stores a value
 * from the database beside a literal description is then not told its value is
 * printed raw.
 *
 * A part is a path of steps down from the parameter: a literal key, {@see ANY}
 * for any element, which a `foreach` value or a computed key reads, and
 * {@see KEYS} for the keys, which a `foreach` key or `array_keys()` reads. A
 * read is followed back through assignments, loop values and joins to the
 * parameter, by operand, to {@see Shape::DEPTH} steps. A write into an element
 * of a parameter reads nothing of it.
 *
 * Under each node the body reads by literal key, {@see OTHERS} stands for
 * every literal key it does not name there. A caller's element under such a
 * key goes to that part rather than the node's, so it cannot reach the reads
 * of the keys the body does name. See {@see Shape::others()}.
 *
 * This only picks which parts get a number of their own. The numbers then
 * travel with the taint, so a read this misses still sees the parts it touches
 * by dataflow, and at worst the parameter's own number, part 0, which covers
 * everything no named part does.
 */
final class ParameterParts
{
    /** Any element: a `foreach` value, or a read with a computed key. */
    public const ANY = '*';

    /** The keys: a `foreach` key, or `array_keys()`. */
    public const KEYS = '#keys';

    /** Every literal key the body does not name under this node. */
    public const OTHERS = '#others';

    /** How far a value is followed back through assignments and joins. */
    private const MAX_HOPS = 32;

    /** @var array<int, true> operands being followed, to stop at a cycle */
    private array $visiting = [];

    /**
     * @param array<int, int> $indexes a parameter operand's object id => its index
     */
    private function __construct(private readonly array $indexes)
    {
    }

    /**
     * @return array<int, list<list<int|string>>> parameter index => its parts, shortest first; part
     *                                            `n + 1` is the one at position `n`
     */
    public static function of(Func $func): array
    {
        $indexes = [];

        foreach (array_values($func->params) as $index => $param) {
            if (! $param->variadic) {
                $indexes[spl_object_id($param->result)] = $index;
            }
        }

        if ($indexes === []) {
            return [];
        }

        $finder = new self($indexes);

        /** @var array<int, array<string, list<int|string>>> $parts */
        $parts = [];

        foreach (BlockOrder::of($func->cfg) as $block) {
            foreach ($block->children as $op) {
                foreach ($finder->partsReadBy($op) as [$index, $path]) {
                    $parts[$index][self::describe($path)] = $path;
                }
            }
        }

        $byIndex = [];

        foreach ($indexes as $index) {
            $list = array_values($parts[$index] ?? []);
            usort(
                $list,
                static fn (array $a, array $b): int => [count($a), self::describe($a)]
                    <=> [count($b), self::describe($b)],
            );
            $byIndex[$index] = self::withOthers(array_slice($list, 0, TaintSet::MAX_PARTS - 1));
        }

        ksort($byIndex);

        return $byIndex;
    }

    /**
     * `$parts` with an {@see OTHERS} part under the parameter itself and under
     * each node that a part names a literal key of, shallowest first, while
     * there is room. Every part the body reads keeps its number.
     *
     * The one under the parameter is there even when the body names no key,
     * so `function acme_id( $a ) { return $a; }` hands each element back
     * under its own key.
     *
     * @param list<list<int|string>> $parts
     *
     * @return list<list<int|string>>
     */
    private static function withOthers(array $parts): array
    {
        $nodes = [self::describe([]) => []];

        foreach ($parts as $path) {
            $last = $path === [] ? null : $path[count($path) - 1];

            if ($last !== null && $last !== self::ANY && $last !== self::KEYS) {
                $node = array_slice($path, 0, -1);
                $nodes[self::describe($node)] = $node;
            }
        }

        $nodes = array_values($nodes);
        usort(
            $nodes,
            static fn (array $a, array $b): int => [count($a), self::describe($a)] <=> [count($b), self::describe($b)],
        );

        foreach ($nodes as $node) {
            if (count($parts) >= TaintSet::MAX_PARTS - 1) {
                break;
            }

            $parts[] = [...$node, self::OTHERS];
        }

        return $parts;
    }

    /**
     * The literal keys a part names directly under `$node`.
     *
     * @param list<list<int|string>> $parts
     * @param list<int|string>       $node
     *
     * @return list<int|string>
     */
    public static function namedUnder(array $parts, array $node): array
    {
        $depth = count($node);
        $named = [];

        foreach ($parts as $path) {
            if (count($path) !== $depth + 1 || array_slice($path, 0, $depth) !== $node) {
                continue;
            }

            $step = $path[$depth] ?? self::ANY;

            if ($step !== self::ANY && $step !== self::KEYS && $step !== self::OTHERS) {
                $named[] = $step;
            }
        }

        return $named;
    }

    /**
     * A path as text, for ordering and for a trace: `[*]['desc']`, `#keys`.
     *
     * @param list<int|string> $path
     */
    public static function describe(array $path): string
    {
        $text = '';

        foreach ($path as $step) {
            $text .= match (true) {
                $step === self::ANY => '[*]',
                $step === self::KEYS => '#keys',
                $step === self::OTHERS => '[others]',
                is_int($step) => '[' . $step . ']',
                default => "['" . $step . "']",
            };
        }

        return $text;
    }

    /**
     * The parts of a parameter this op reads, each with the parameter's index.
     *
     * @return list<array{int, list<int|string>}>
     */
    private function partsReadBy(Op $op): array
    {
        if ($op instanceof Op\Expr\ArrayDimFetch) {
            // A write lowers to a fetch whose result an assignment then writes:
            // `$p['k'] = $v` reads nothing of `$p['k']`.
            if (
                $op->dim === null
                || $op->dim instanceof Operand\NullOperand
                || OperandHelper::isWrittenElsewhere($op->result, $op)
            ) {
                return [];
            }

            return $this->below($op->var, self::keyStep($op->dim));
        }

        if ($op instanceof Op\Iterator\Value) {
            return $this->below($op->var, self::ANY);
        }

        if ($op instanceof Op\Iterator\Key) {
            return $this->below($op->var, self::KEYS);
        }

        if (
            ($op instanceof Op\Expr\FuncCall || $op instanceof Op\Expr\NsFuncCall)
            && ($op->args[0] ?? null) instanceof Operand
        ) {
            $name = OperandHelper::literalString($op->name);

            if ($name !== null && strtolower(ltrim($name, '\\')) === 'array_keys') {
                return $this->below($op->args[0], self::KEYS);
            }
        }

        return [];
    }

    /**
     * The step a read with key `$dim` takes: {@see ANY} for a key computed at
     * run time, and otherwise {@see step()}.
     */
    private static function keyStep(Operand $dim): int|string
    {
        $key = OperandHelper::literalKey($dim);

        return $key === null ? self::ANY : self::step($key);
    }

    /**
     * A literal key as a step: the key as PHP stores it, so `'1'` is `1`. A
     * key spelt like one of the special steps is read as any element, which
     * covers every literal key, so it can never be taken for the keys or for
     * the keys the body does not name.
     */
    public static function step(int|string $key): int|string
    {
        if ($key === self::ANY || $key === self::KEYS || $key === self::OTHERS) {
            return self::ANY;
        }

        return array_key_first([$key => true]);
    }

    /**
     * The part one step below `$operand`, when `$operand` is a part of a
     * parameter.
     *
     * @return list<array{int, list<int|string>}>
     */
    private function below(Operand $operand, int|string $step): array
    {
        $at = $this->pathOf($operand, 0);

        if ($at === null || count($at[1]) >= Shape::DEPTH) {
            return [];
        }

        return [[$at[0], [...$at[1], $step]]];
    }

    /**
     * The parameter an operand is a part of, and the path to that part.
     *
     * @return array{int, list<int|string>}|null
     */
    private function pathOf(Operand $operand, int $hops): ?array
    {
        $id = spl_object_id($operand);

        if (isset($this->indexes[$id])) {
            return [$this->indexes[$id], []];
        }

        if ($hops >= self::MAX_HOPS || isset($this->visiting[$id])) {
            return null;
        }

        $this->visiting[$id] = true;

        try {
            $op = OperandHelper::definingOp($operand);

            return match (true) {
                $op instanceof Op\Expr\Assign,
                $op instanceof Op\Expr\Assertion => $this->pathOf($op->expr, $hops + 1),
                $op instanceof Op\Expr\ArrayDimFetch => $this->stepDown(
                    $this->pathOf($op->var, $hops + 1),
                    $op->dim === null ? null : self::keyStep($op->dim),
                ),
                $op instanceof Op\Iterator\Value => $this->stepDown($this->pathOf($op->var, $hops + 1), self::ANY),
                $op instanceof Op\Phi => $this->agreed($op, $hops),
                default => null,
            };
        } finally {
            unset($this->visiting[$id]);
        }
    }

    /**
     * @param array{int, list<int|string>}|null $at
     *
     * @return array{int, list<int|string>}|null
     */
    private function stepDown(?array $at, int|string|null $step): ?array
    {
        if ($at === null || $step === null || count($at[1]) >= Shape::DEPTH) {
            return null;
        }

        return [$at[0], [...$at[1], $step]];
    }

    /**
     * The part a join is, when every input that is a part agrees on which.
     * An input that is no part adds nothing a part could carry, so it is left
     * out, as a literal default is: `$x = $flag ? $p['a'] : ''`.
     *
     * @return array{int, list<int|string>}|null
     */
    private function agreed(Op\Phi $phi, int $hops): ?array
    {
        $found = null;

        foreach ($phi->vars as $var) {
            if (! $var instanceof Operand) {
                continue;
            }

            $at = $this->pathOf($var, $hops + 1);

            if ($at === null) {
                continue;
            }

            if ($found !== null && $found !== $at) {
                return null;
            }

            $found = $at;
        }

        return $found;
    }
}
