<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

/**
 * Lowers modern PHP that `ircmaxell/php-cfg` v0.8.1 cannot parse into
 * equivalent older syntax, before the CFG is built.
 *
 * php-cfg predates a lot of the language. Against real plugin code it throws on
 * six constructs:
 *
 * | Construct                | Since | Lowered to |
 * | ------------------------ | ----- | ---------- |
 * | `match`                  | 8.0   | a ternary chain |
 * | `?->`                    | 8.0   | `->` |
 * | `enum`                   | 8.1   | a final class with the cases as constants |
 * | `f(...)`                 | 8.1   | the equivalent callable string or array |
 * | `A&B`                    | 8.1   | the first named type |
 * | `(A&B)\|null`            | 8.2   | the same, inside the union |
 *
 * It also folds the identity magic constants — `__NAMESPACE__`, `__CLASS__`,
 * `__FUNCTION__`, `__METHOD__`, `__TRAIT__` — to the strings they stand for.
 * Not a compatibility fix: php-cfg parses them fine, but leaves them opaque, and
 * `add_filter( 'hook', __NAMESPACE__ . '\\render' )` is how namespaced plugins
 * register a callback. Folding here rather than in the value resolver means the
 * enclosing namespace and class are still in hand, and everything downstream
 * gets it for free.
 *
 * `__DIR__` and `__FILE__` are deliberately left alone. They belong to include
 * resolution, where the path matters for more than its value.
 *
 * Two of those — `match` and `?->` — have been in the language since PHP 8.0
 * and are ordinary in any plugin written in the last few years. Without this
 * shim the corpus parse rate falls far below the 99.5% the project treats as a
 * kill gate, and every unparsed file is a silent false negative.
 *
 * Every rewrite is semantics-preserving *for taint purposes*, which is a weaker
 * bar than being semantics-preserving in general, and the differences are noted
 * on each method. Positions are copied from the original node so findings still
 * point at the real source line.
 *
 * This is the whole reason the plan says to vendor php-cfg behind an adapter.
 * Replacing or forking it later touches this file and {@see CfgBuilder}.
 */
final class CompatibilityVisitor extends NodeVisitorAbstract
{
    /** @var array<string, int> */
    private array $lowered = [];

    private string $namespace = '';

    /** @var list<string> */
    private array $classStack = [];

    /** @var list<string> */
    private array $functionStack = [];

    /**
     * Depth of enclosing traits.
     *
     * A trait's `__CLASS__` is the *using* class at runtime, which is not known
     * statically, so it is left opaque rather than folded to a wrong answer.
     */
    private int $traitDepth = 0;

    /**
     * Which constructs were rewritten, for `dump-cfg --show-lowering`.
     *
     * @return array<string, int>
     */
    public function lowered(): array
    {
        ksort($this->lowered);

        return $this->lowered;
    }

    public function enterNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->namespace = $node->name?->toString() ?? '';
        }

        if ($node instanceof Node\Stmt\Trait_) {
            $this->traitDepth++;
        }

        if ($node instanceof Node\Stmt\ClassLike) {
            $this->classStack[] = $node->name === null
                ? ''
                : ltrim($this->namespace . '\\' . $node->name->toString(), '\\');
        }

        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_) {
            $this->functionStack[] = $node->name->toString();
        } elseif ($node instanceof Node\FunctionLike) {
            $this->functionStack[] = '{closure}';
        }

        return null;
    }

    public function leaveNode(Node $node): ?Node
    {
        if ($node instanceof Node\Stmt\Trait_) {
            $this->traitDepth--;
        }

        if ($node instanceof Node\Stmt\ClassLike) {
            array_pop($this->classStack);
        }

        if ($node instanceof Node\FunctionLike) {
            array_pop($this->functionStack);
        }

        return match (true) {
            $node instanceof Node\Scalar\MagicConst => $this->foldMagicConstant($node),
            $node instanceof Node\Expr\Match_ => $this->lowerMatch($node),
            $node instanceof Node\Expr\NullsafePropertyFetch => $this->lowerNullsafePropertyFetch($node),
            $node instanceof Node\Expr\NullsafeMethodCall => $this->lowerNullsafeMethodCall($node),
            $node instanceof Node\Stmt\EnumCase => $this->lowerEnumCase($node),
            $node instanceof Node\Stmt\Enum_ => $this->lowerEnum($node),
            $node instanceof Node\IntersectionType => $this->lowerIntersectionType($node),
            $node instanceof Node\Expr\YieldFrom => $this->lowerYieldFrom($node),
            $node instanceof Node\StaticVar => $this->giveStaticVarADefault($node),
            $node instanceof Node\Expr\FuncCall,
            $node instanceof Node\Expr\MethodCall,
            $node instanceof Node\Expr\StaticCall,
            $node instanceof Node\Expr\New_ => $this->lowerFirstClassCallable($node),
            default => null,
        };
    }

    /**
     * The identity magic constants, as the strings they stand for.
     *
     * A trait's `__CLASS__` is the *using* class at runtime, which is not known
     * statically, so a trait is left alone rather than folded to the trait's own
     * name — a wrong answer would be worse than an opaque one.
     */
    private function foldMagicConstant(Node\Scalar\MagicConst $node): ?Node
    {
        $class = end($this->classStack) === false ? '' : (string) end($this->classStack);
        $function = end($this->functionStack) === false ? '' : (string) end($this->functionStack);
        $inTrait = $this->traitDepth > 0;

        $value = match (true) {
            $node instanceof Node\Scalar\MagicConst\Namespace_ => $this->namespace,
            $node instanceof Node\Scalar\MagicConst\Class_ => $inTrait ? null : $class,
            $node instanceof Node\Scalar\MagicConst\Function_ => $function,
            $node instanceof Node\Scalar\MagicConst\Method => $class === ''
                ? $function
                : $class . '::' . $function,
            default => null,
        };

        if ($value === null) {
            return null;
        }

        $this->record('magic_constant');

        return new Node\Scalar\String_($value, $node->getAttributes());
    }

    private function record(string $construct): void
    {
        $this->lowered[$construct] = ($this->lowered[$construct] ?? 0) + 1;
    }

    /**
     * `match ($x) { a, b => P; default => Q; }` becomes
     * `($x === a || $x === b) ? P : Q`.
     *
     * Two differences from real `match`, both acceptable here:
     *
     * - A `match` with no matching arm and no default throws
     *   `UnhandledMatchError`. The ternary chain yields the last arm instead.
     *   The engine does not model exception control flow anyway.
     * - The subject expression is repeated once per arm, so a subject with side
     *   effects is analysed several times. Findings inside it de-duplicate by
     *   rule, line and column, so this shows up as extra work rather than extra
     *   output.
     */
    private function lowerMatch(Node\Expr\Match_ $node): Node\Expr
    {
        $this->record('match');

        $default = null;
        $conditional = [];

        foreach ($node->arms as $arm) {
            if ($arm->conds === null) {
                $default = $arm->body;

                continue;
            }

            $conditional[] = $arm;
        }

        $result = $default ?? new Node\Expr\ConstFetch(new Node\Name('null'), $node->getAttributes());

        foreach (array_reverse($conditional) as $arm) {
            /** @var Node\MatchArm $arm */
            $condition = null;

            foreach ($arm->conds ?? [] as $value) {
                $comparison = new Node\Expr\BinaryOp\Identical($node->cond, $value, $node->getAttributes());
                $condition = $condition === null
                    ? $comparison
                    : new Node\Expr\BinaryOp\BooleanOr($condition, $comparison, $node->getAttributes());
            }

            if ($condition === null) {
                continue;
            }

            $result = new Node\Expr\Ternary($condition, $arm->body, $result, $node->getAttributes());
        }

        return $result;
    }

    /**
     * `$a?->b` becomes `$a->b`. The two differ only in short-circuiting on
     * null, which carries no taint either way.
     */
    private function lowerNullsafePropertyFetch(Node\Expr\NullsafePropertyFetch $node): Node\Expr
    {
        $this->record('nullsafe-property-fetch');

        return new Node\Expr\PropertyFetch($node->var, $node->name, $node->getAttributes());
    }

    private function lowerNullsafeMethodCall(Node\Expr\NullsafeMethodCall $node): Node\Expr
    {
        $this->record('nullsafe-method-call');

        return new Node\Expr\MethodCall($node->var, $node->name, $node->args, $node->getAttributes());
    }

    /**
     * `case Draft = 'draft';` becomes `const Draft = 'draft';`.
     *
     * A pure case with no backing value becomes a constant holding its own
     * name, which is what `->name` would have returned.
     */
    private function lowerEnumCase(Node\Stmt\EnumCase $node): Node\Stmt
    {
        $this->record('enum-case');

        $value = $node->expr ?? new Node\Scalar\String_($node->name->toString(), $node->getAttributes());

        return new Node\Stmt\ClassConst(
            [new Node\Const_($node->name, $value, $node->getAttributes())],
            0,
            $node->getAttributes(),
            array_values($node->attrGroups),
        );
    }

    /**
     * `enum S: string { ... }` becomes `final class S { ... }`.
     *
     * The method bodies are the part that matters — an enum method can echo a
     * tainted value like any other method — and they carry over untouched.
     */
    private function lowerEnum(Node\Stmt\Enum_ $node): Node\Stmt
    {
        $this->record('enum');

        return new Node\Stmt\Class_(
            $node->name,
            [
                'flags' => Node\Stmt\Class_::MODIFIER_FINAL,
                'implements' => $node->implements,
                'stmts' => $node->stmts,
                'attrGroups' => $node->attrGroups,
            ],
            $node->getAttributes(),
        );
    }

    /**
     * `yield from $inner` becomes `yield $inner`.
     *
     * The two differ in what the generator yields — the delegate's values
     * rather than the delegate itself — but not in where the data came from,
     * which is the only question taint asks.
     */
    private function lowerYieldFrom(Node\Expr\YieldFrom $node): Node\Expr
    {
        $this->record('yield-from');

        return new Node\Expr\Yield_($node->expr, null, $node->getAttributes());
    }

    /**
     * `static $x;` becomes `static $x = null;`.
     *
     * Not a language gap but a bug in php-cfg: it declares
     * `Op\Terminal\StaticVar::$defaultVar` as a typed nullable property and
     * then only assigns it when a default is present, so with no initialiser
     * the property stays *uninitialised* rather than null. Its own Simplifier
     * reads it through `getVariableNames()` and throws.
     *
     * `static $x;` already initialises to null on first call, so writing that
     * out changes nothing and it accounted for 33 of the 36 corpus parse
     * failures — roughly one file in 750, concentrated in the most widely
     * installed plugins there are.
     */
    private function giveStaticVarADefault(Node\StaticVar $node): ?Node
    {
        if ($node->default !== null) {
            return null;
        }

        $this->record('static-var-without-default');

        return new Node\StaticVar(
            $node->var,
            new Node\Expr\ConstFetch(new Node\Name('null'), $node->getAttributes()),
            $node->getAttributes(),
        );
    }

    /**
     * `A&B` becomes `A`.
     *
     * The declared type is used for exactly one thing — resolving the class of
     * a method call's receiver — and any member of the intersection is a valid
     * answer for that.
     */
    private function lowerIntersectionType(Node\IntersectionType $node): Node
    {
        $this->record('intersection-type');

        foreach ($node->types as $type) {
            if ($type instanceof Node\Name || $type instanceof Node\Identifier) {
                return $type;
            }
        }

        return new Node\Identifier('mixed', $node->getAttributes());
    }

    /**
     * `strlen(...)` becomes `'strlen'`, `Foo::bar(...)` becomes `'Foo::bar'`,
     * `$o->m(...)` becomes `[$o, 'm']`.
     *
     * Those are the callable forms the same expression would have taken before
     * 8.1, and they are what the analyser already knows how to read.
     */
    private function lowerFirstClassCallable(
        Node\Expr\FuncCall|Node\Expr\MethodCall|Node\Expr\StaticCall|Node\Expr\New_ $node,
    ): ?Node\Expr {
        if (! $node->isFirstClassCallable()) {
            return null;
        }

        $this->record('first-class-callable');
        $attributes = $node->getAttributes();

        if ($node instanceof Node\Expr\New_) {
            // `new Foo(...)` is not valid PHP, but guard rather than assume.
            return new Node\Expr\ConstFetch(new Node\Name('null'), $attributes);
        }

        if ($node instanceof Node\Expr\FuncCall) {
            return $node->name instanceof Node\Name
                ? new Node\Scalar\String_($node->name->toString(), $attributes)
                : $node->name;
        }

        if ($node instanceof Node\Expr\StaticCall) {
            if ($node->class instanceof Node\Name && $node->name instanceof Node\Identifier) {
                return new Node\Scalar\String_(
                    $node->class->toString() . '::' . $node->name->toString(),
                    $attributes,
                );
            }

            return new Node\Expr\ConstFetch(new Node\Name('null'), $attributes);
        }

        if (! $node->name instanceof Node\Identifier) {
            return new Node\Expr\ConstFetch(new Node\Name('null'), $attributes);
        }

        return new Node\Expr\Array_(
            [
                new Node\ArrayItem($node->var, null, false, $attributes),
                new Node\ArrayItem(
                    new Node\Scalar\String_($node->name->toString(), $attributes),
                    null,
                    false,
                    $attributes,
                ),
            ],
            $attributes,
        );
    }
}
