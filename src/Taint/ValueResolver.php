<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ConstantReturnTable;
use Enshrined\WpTaint\Cfg\ConstantTable;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Follows an operand back to the constant values it can hold.
 *
 * WordPress code names things with strings constantly — callbacks, hook names,
 * class names for `new $class` — and a taint analyser that treats every one of
 * those as opaque gives up exactly where the interesting flows are. This walks
 * the SSA graph backwards until it either lands on literals or runs out of
 * things it can follow.
 *
 * A **set**, not a value: a phi node at a branch join genuinely holds one of
 * several strings, and picking one would be a guess. Returning all of them lets
 * the caller union the effects, which is the sound answer.
 *
 * Returning an empty set means "no idea", never "no values". The two have very
 * different consequences downstream and callers have to tell them apart.
 */
final class ValueResolver
{
    public function __construct(
        private readonly ?ConstantTable $constants = null,
        private readonly ?ConstantReturnTable $returns = null,
    ) {
    }

    /**
     * The same resolver, able to see a constant table.
     *
     * Returns a new instance rather than mutating, because the table is built
     * by running the resolver over the code — and a resolver that gained
     * knowledge halfway through a walk would give different answers to the same
     * question depending on when it was asked.
     */
    public function withConstants(ConstantTable $constants, ?ConstantReturnTable $returns = null): self
    {
        return new self($constants, $returns);
    }

    /**
     * How far back to walk before giving up.
     *
     * Chains longer than this exist, but they are almost always a sign the
     * value is genuinely computed rather than merely passed around, in which
     * case the answer would be "no idea" anyway.
     */
    private const MAX_DEPTH = 12;

    /**
     * How many distinct values to carry before declaring defeat.
     *
     * A concat of two phis of four values each is sixteen strings, and past
     * that point the "resolved" set is broad enough to be worthless while
     * still costing a call site's worth of analysis each.
     */
    private const MAX_VALUES = 12;

    /**
     * The constant strings this operand can hold.
     *
     * @return list<string> empty when the value cannot be pinned down
     */
    public function strings(Operand $operand, int $depth = 0): array
    {
        if ($depth > self::MAX_DEPTH) {
            return [];
        }

        $literal = OperandHelper::literalString($operand);

        if ($literal !== null) {
            return [$literal];
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            return [];
        }

        return match (true) {
            $definition instanceof Op\Expr\Assign => $this->strings($definition->expr, $depth + 1),
            $definition instanceof Op\Expr\ConstFetch => $this->fromConstant($definition),
            $definition instanceof Op\Expr\FuncCall,
            $definition instanceof Op\Expr\NsFuncCall => $this->fromPureCall($definition, $depth),
            $definition instanceof Op\Expr\MethodCall,
            $definition instanceof Op\Expr\StaticCall => $this->fromConstantReturn($definition),
            $definition instanceof Op\Phi => $this->fromPhi($definition, $depth),
            $definition instanceof Op\Expr\ConcatList => $this->fromParts($definition->list, $depth),
            $definition instanceof Op\Expr\BinaryOp\Concat => $this->fromParts(
                [$definition->left, $definition->right],
                $depth,
            ),
            default => [],
        };
    }

    /**
     * Path helpers whose result depends on nothing but their arguments.
     *
     * `define( 'WPCF7_PLUGIN_DIR', untrailingslashit( dirname( WPCF7_PLUGIN ) ) )`
     * is how WordPress plugins declare their own directory, and without these
     * the constant is unresolvable and so is every path built from it — Contact
     * Form 7 resolved none of its 61 includes.
     *
     * Only functions that are total, deterministic and free of filesystem
     * access. `realpath()` is deliberately absent: it answers a question about
     * the machine running the scan, not about the code.
     *
     */
    private const PURE = [
        'dirname', 'basename', 'trailingslashit', 'untrailingslashit',
        'plugin_dir_path', 'wp_normalize_path', 'ltrim', 'rtrim', 'trim',
        'strtolower', 'strtoupper', 'str_replace',
    ];

    /**
     * Evaluate a call whose arguments all resolve and whose result depends on
     * nothing else.
     *
     * @return list<string>
     */
    private function fromPureCall(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op, int $depth): array
    {
        $name = $this->pureFunctionName($op);

        if ($name === null) {
            // Not a builtin this can evaluate, but perhaps a function in the
            // scan whose body always returns the same string.
            foreach ($this->callNames($op) as $candidate) {
                $value = $this->returns?->forFunction($candidate);

                if ($value !== null) {
                    return [$value];
                }
            }

            return [];
        }

        $arguments = [];

        foreach ($op->args as $argument) {
            if (! $argument instanceof Operand) {
                return [];
            }

            $resolved = $this->strings($argument, $depth + 1);

            // One value per argument. A set would mean a cross product, and a
            // path helper applied to an ambiguous path is not worth the
            // combinatorics.
            if (count($resolved) !== 1) {
                return [];
            }

            $arguments[] = $resolved[0];
        }

        $value = self::applyPure($name, $arguments);

        return $value === null ? [] : [$value];
    }

    /**
     * A method whose body always returns the same string.
     *
     * `WC()->plugin_path()` names a method on a receiver whose class this
     * cannot see — `WC()` returns an instance, not a string — so it resolves by
     * method name, and only when exactly one class in the scan declares it.
     *
     * @return list<string>
     */
    private function fromConstantReturn(Op\Expr\MethodCall|Op\Expr\StaticCall $op): array
    {
        if ($this->returns === null) {
            return [];
        }

        $method = OperandHelper::literalString($op->name);

        if ($method === null) {
            return [];
        }

        if ($op instanceof Op\Expr\StaticCall) {
            $class = OperandHelper::literalString($op->class);

            if ($class !== null) {
                $value = $this->returns->forFunction($class . '::' . $method);

                if ($value !== null) {
                    return [$value];
                }
            }
        }

        $value = $this->returns->forUniqueMethod($method);

        return $value === null ? [] : [$value];
    }

    /**
     * @return list<string>
     */
    private function callNames(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): array
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        $resolved = [];

        foreach ($names as $name) {
            if ($name !== null) {
                $resolved[] = ltrim($name, '\\');
            }
        }

        return $resolved;
    }

    private function pureFunctionName(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op): ?string
    {
        $names = $op instanceof Op\Expr\NsFuncCall
            ? [OperandHelper::literalString($op->nsName), OperandHelper::literalString($op->name)]
            : [OperandHelper::literalString($op->name)];

        foreach ($names as $candidate) {
            if ($candidate === null) {
                continue;
            }

            $lower = strtolower(ltrim($candidate, '\\'));

            if (in_array($lower, self::PURE, true)) {
                return $lower;
            }
        }

        return null;
    }

    /**
     * @param list<string> $arguments
     */
    private static function applyPure(string $name, array $arguments): ?string
    {
        $first = $arguments[0] ?? null;

        if ($first === null) {
            return null;
        }

        return match ($name) {
            'dirname' => count($arguments) > 1
                ? null
                : dirname($first),
            'basename' => count($arguments) > 2 ? null : basename($first, $arguments[1] ?? ''),
            'trailingslashit' => rtrim(str_replace('\\', '/', $first), '/') . '/',
            // plugin_dir_path() is trailingslashit( dirname( … ) ). Forgetting
            // the dirname turned JETPACK__PLUGIN_DIR into '…/jetpack.php/' and
            // took every include built from it with it.
            'plugin_dir_path' => rtrim(str_replace('\\', '/', dirname($first)), '/') . '/',
            'untrailingslashit' => rtrim(str_replace('\\', '/', $first), '/'),
            'wp_normalize_path' => str_replace('\\', '/', $first),
            'ltrim' => count($arguments) > 2 ? null : ltrim($first, $arguments[1] ?? " \t\n\r\0\x0B"),
            'rtrim' => count($arguments) > 2 ? null : rtrim($first, $arguments[1] ?? " \t\n\r\0\x0B"),
            'trim' => count($arguments) > 2 ? null : trim($first, $arguments[1] ?? " \t\n\r\0\x0B"),
            'strtolower' => count($arguments) > 1 ? null : strtolower($first),
            'strtoupper' => count($arguments) > 1 ? null : strtoupper($first),
            'str_replace' => count($arguments) === 3 ? str_replace($first, $arguments[1], $arguments[2]) : null,
            default => null,
        };
    }

    /**
     * A constant's value, from the table built over the whole scan.
     *
     * WordPress builds paths out of constants and almost nothing else, so this
     * is what makes `require_once ACME_DIR . 'inc/settings.php'` resolvable at
     * all.
     *
     * @return list<string>
     */
    private function fromConstant(Op\Expr\ConstFetch $op): array
    {
        if ($this->constants === null) {
            return [];
        }

        // A namespaced constant falls back to the global one when the
        // namespaced one does not exist, so both names have to be tried.
        foreach ([$op->nsName, $op->name] as $operand) {
            if ($operand === null) {
                continue;
            }

            $name = OperandHelper::literalString($operand);

            if ($name === null) {
                continue;
            }

            $values = $this->constants->valuesOf($name);

            if ($values !== []) {
                return $values;
            }
        }

        return [];
    }

    /**
     * The literal pair behind `array( $receiver, 'method' )`.
     *
     * PHP's array callable form. The first element is either an object operand
     * or a class-name string, and the callable resolver needs to tell those
     * apart, so the operand is handed back rather than resolved here.
     *
     * @return array{0: Operand, 1: list<string>}|null
     */
    public function callableArray(Operand $operand, int $depth = 0): ?array
    {
        if ($depth > self::MAX_DEPTH) {
            return null;
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->callableArray($definition->expr, $depth + 1);
        }

        if (! $definition instanceof Op\Expr\Array_) {
            return null;
        }

        $values = [];

        foreach ($definition->values as $value) {
            if ($value instanceof Operand) {
                $values[] = $value;
            }
        }

        if (count($values) !== 2) {
            return null;
        }

        $methods = $this->strings($values[1], $depth + 1);

        return $methods === [] ? null : [$values[0], $methods];
    }

    /**
     * Every branch of a join contributes, because at runtime any of them can be
     * the one taken.
     *
     * @return list<string>
     */
    private function fromPhi(Op\Phi $phi, int $depth): array
    {
        $values = [];

        foreach ($phi->vars as $var) {
            if (! $var instanceof Operand) {
                continue;
            }

            foreach ($this->strings($var, $depth + 1) as $value) {
                if (! in_array($value, $values, true)) {
                    $values[] = $value;
                }
            }

            if (count($values) > self::MAX_VALUES) {
                return [];
            }
        }

        return $values;
    }

    /**
     * A concatenation resolves only if every part does.
     *
     * One unresolvable part means the whole string is unknown — `'render_' .
     * $mode` where `$mode` is a parameter could be anything, and treating the
     * prefix as the answer would resolve the call to the wrong function.
     *
     * @param array<array-key, mixed> $parts
     *
     * @return list<string>
     */
    private function fromParts(array $parts, int $depth): array
    {
        $combinations = [''];

        foreach ($parts as $part) {
            if (! $part instanceof Operand) {
                return [];
            }

            $options = $this->strings($part, $depth + 1);

            if ($options === []) {
                return [];
            }

            $next = [];

            foreach ($combinations as $prefix) {
                foreach ($options as $option) {
                    $next[] = $prefix . $option;
                }
            }

            if (count($next) > self::MAX_VALUES) {
                return [];
            }

            $combinations = $next;
        }

        return array_values(array_unique($combinations));
    }
}
