<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ConstantReturnTable;
use Enshrined\WpTaint\Cfg\ConstantTable;
use Enshrined\WpTaint\Cfg\ThemeRoots;
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
        private readonly ?ThemeRoots $themes = null,
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
        return new self($constants, $returns, $this->themes);
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
            $definition instanceof Op\Expr\NsFuncCall => $this->fromCall($definition, $depth),
            $definition instanceof Op\Expr\MethodCall,
            $definition instanceof Op\Expr\StaticCall => $this->fromConstantReturn($definition, $depth),
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
    /**
     * Theme-location functions the calling file itself answers.
     *
     * `get_template_directory()` asks "where is the active theme" at runtime,
     * and the static answer is the theme the calling file is in — see
     * {@see ThemeRoots}. Themes hang their whole constant chain off it:
     *
     *     define( 'ACME_THEME_PATH', get_template_directory() . '/' );
     *     define( 'ACME_THEME_INC', ACME_THEME_PATH . 'includes/' );
     *     require_once ACME_THEME_INC . 'core.php';
     *
     * so without this fold every one of those includes is unresolvable.
     *
     * `get_stylesheet_directory()` is the file's own theme;
     * `get_template_directory()` is its declared parent when the scan holds it,
     * read from style.css the way WordPress reads it. A file outside every
     * theme folds to all candidates, the union any multi-valued answer gets.
     *
     * `get_theme_file_path( $file )` applies the child-overrides-parent order
     * against the scanned file list; `get_parent_theme_file_path()` goes
     * straight to the parent.
     */
    /**
     * @return list<string>
     */
    private function fromCall(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op, int $depth): array
    {
        $theme = $this->fromThemeLocation($op, $depth);

        if ($theme !== []) {
            return $theme;
        }

        $pure = $this->fromPureCall($op, $depth);

        if ($pure !== []) {
            return $pure;
        }

        foreach ($this->callNames($op) as $name) {
            $folded = $this->foldUserCall($name, null, $op->args, $depth);

            if ($folded !== []) {
                return $folded;
            }
        }

        return [];
    }

    /**
     * A user function's constant or templated return, folded at this call.
     *
     * The template form is what a path helper compiles to:
     *
     *     public static function get_view_filename( $view ) {
     *         return __DIR__ . "/views/$view";
     *     }
     *     include self::get_view_filename( 'html-main.php' );
     *
     * The return depends only on the argument, the argument is a literal, so
     * the fold is exact. An argument that does not fold to exactly one string
     * folds to nothing, never to a guess.
     *
     * @param array<array-key, mixed> $arguments
     *
     * @return list<string>
     */
    private function foldUserCall(string $name, ?string $method, array $arguments, int $depth): array
    {
        if ($this->returns === null) {
            return [];
        }

        $template = $method !== null
            ? ($this->returns->templateFor($name) ?? $this->returns->templateForUniqueMethod($method))
            : $this->returns->templateFor($name);

        if ($template === null) {
            return [];
        }

        $folded = '';

        foreach ($template as $segment) {
            if (is_string($segment)) {
                $folded .= $segment;

                continue;
            }

            $argument = array_values($arguments)[$segment] ?? null;

            if (! $argument instanceof Operand) {
                return [];
            }

            $values = $this->strings($argument, $depth + 1);

            if (count($values) !== 1) {
                return [];
            }

            $folded .= $values[0];
        }

        return [$folded];
    }

    /**
     * @return list<string>
     */
    private function fromThemeLocation(Op\Expr\FuncCall|Op\Expr\NsFuncCall $op, int $depth): array
    {
        if ($this->themes === null || $this->themes->isEmpty()) {
            return [];
        }

        $name = $this->pureFunctionName($op) ?? $this->callNames($op)[0] ?? null;
        $name = $name === null ? null : strtolower(ltrim($name, '\\'));

        $calling = $op->getFile();

        switch ($name) {
            case 'get_stylesheet_directory':
                return $this->themes->stylesheetRootsFor($calling);

            case 'get_template_directory':
                return $this->themes->templateRootsFor($calling);

            case 'get_theme_file_path':
            case 'get_parent_theme_file_path':
                $file = $op->args[0] ?? null;

                if (! $file instanceof Operand) {
                    return [];
                }

                $values = $this->strings($file, $depth + 1);

                if (count($values) !== 1) {
                    return [];
                }

                if ($name === 'get_parent_theme_file_path') {
                    return array_map(
                        static fn (string $root): string => $root . '/' . ltrim($values[0], '/'),
                        $this->themes->templateRootsFor($calling),
                    );
                }

                return $this->themes->themeFilePathsFor($calling, $values[0]);

            default:
                return [];
        }
    }

    /**
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
    private function fromConstantReturn(Op\Expr\MethodCall|Op\Expr\StaticCall $op, int $depth): array
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

        $qualified = $op instanceof Op\Expr\StaticCall
            ? OperandHelper::literalString($op->class)
            : null;

        $templated = $this->foldUserCall(
            ($qualified !== null ? $qualified . '::' : '') . $method,
            $method,
            $op->args,
            $depth,
        );

        if ($templated !== []) {
            return $templated;
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
     * The literal head of a string whose tail will not fold.
     *
     * `"save_{$type}"` is no string {@see strings} can answer, and treating
     * the prefix as the whole name would resolve to the wrong thing — but the
     * prefix *is* an honest answer to a different question: "what must this
     * name start with?" The hook graph uses it to join a dynamic dispatch to
     * the literal registrations it can reach, and the dynamic registration to
     * the literal dispatches that can reach it.
     *
     * Empty when the operand folds completely (ask {@see strings}), when
     * nothing at its head folds, or when it is not a built string at all.
     *
     * @return list<string>
     */
    public function prefixes(Operand $operand, int $depth = 0): array
    {
        if ($depth > self::MAX_DEPTH) {
            return [];
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition instanceof Op\Expr\Assign) {
            return $this->prefixes($definition->expr, $depth + 1);
        }

        $parts = match (true) {
            $definition instanceof Op\Expr\BinaryOp\Concat => [$definition->left, $definition->right],
            $definition instanceof Op\Expr\ConcatList => $definition->list,
            default => null,
        };

        if ($parts === null) {
            return [];
        }

        $combinations = [''];
        $stopped = false;

        foreach ($parts as $part) {
            if (! $part instanceof Operand) {
                $stopped = true;

                break;
            }

            $options = $this->strings($part, $depth + 1);

            if ($options === []) {
                $stopped = true;

                // The head of this part may itself fold partially — a nested
                // concat whose own tail is the dynamic bit.
                $options = $this->prefixes($part, $depth + 1);

                if ($options !== []) {
                    $combinations = self::combine($combinations, $options);
                }

                break;
            }

            $combinations = self::combine($combinations, $options);

            if ($combinations === []) {
                return [];
            }
        }

        // A string that folded completely is not a prefix — it is an answer to
        // the question {@see strings} asks, and the caller should ask it there.
        if (! $stopped) {
            return [];
        }

        return array_values(array_filter(array_unique($combinations), static fn (string $p): bool => $p !== ''));
    }

    /**
     * @param list<string> $prefixes
     * @param list<string> $options
     *
     * @return list<string>
     */
    private static function combine(array $prefixes, array $options): array
    {
        $next = [];

        foreach ($prefixes as $prefix) {
            foreach ($options as $option) {
                $next[] = $prefix . $option;
            }
        }

        return count($next) > self::MAX_VALUES ? [] : $next;
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
