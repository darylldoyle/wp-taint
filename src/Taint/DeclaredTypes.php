<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * What the code says its own types are, across the whole scan.
 *
 * {@see ClassTypeMap} answers the same question from evidence — a parameter's
 * declared type, a `new Foo()` it watched being assigned — but it is built per
 * function and sees one body at a time. That is not enough for the shape every
 * substantial plugin is made of:
 *
 * ```php
 * function code_snippets(): Plugin { … }          // load.php
 * class Plugin { public DB $db; }                 // Plugin.php
 * class DB {
 *     public function get_table_name(): string {  // DB.php
 *         return $this->table;                    //   = $wpdb->prefix . self::TABLE_NAME
 *     }
 * }
 *
 * $table_name = code_snippets()->db->get_table_name();
 * $wpdb->get_results( "SELECT * FROM $table_name" );
 * ```
 *
 * Every link there is provable and the value is a table name the plugin built
 * out of `$wpdb->prefix` and a class constant. The receiver could not be
 * followed, so the call did not resolve, so the origin was "unaccounted for",
 * so it was reported as an unprepared query. `wpforms()->form->`,
 * `aioseo()->core->db->` and `WC()->countries->` are the same shape.
 *
 * ## Declarations only
 *
 * Nothing here is inferred. A return type is read from `Func::$returnType`,
 * which php-cfg has already resolved to a fully-qualified name — including
 * `self`, which it rewrites to the declaring class. A property type is read
 * from its declaration in the AST. A scalar or absent type is not a class and
 * is skipped, so `function name(): string` contributes nothing.
 *
 * The cost of being wrong is a method call resolved against the wrong class,
 * which is a wrong sink match and a false finding at critical severity. Reading
 * only what the author wrote keeps that cost at zero.
 */
final class DeclaredTypes
{
    public function __construct(private readonly ClassHierarchy $hierarchy = new ClassHierarchy())
    {
    }

    /** @var array<string, string> function key => declared return class */
    private array $returns = [];

    /** @var array<string, string> `class::property` => declared class */
    private array $properties = [];

    /**
     * Property keys seen holding more than one class.
     *
     * A property assigned `new A()` in one method and `new B()` in another is
     * genuinely ambiguous, and guessing either way costs a wrong sink match.
     * The key is dropped rather than resolved to whichever was seen last, so
     * the answer stays deterministic under a different file order.
     *
     * @var array<string, true>
     */
    private array $ambiguous = [];

    /**
     * Read every typed property declaration in a file.
     *
     * Must run while the AST is still held — {@see ParsedFile::releaseAst} is
     * called as soon as the structural rules are done, and this index is built
     * with the function table, which is well before that.
     */
    public function observeFile(ParsedFile $file): void
    {
        foreach ((new NodeFinder())->findInstanceOf($file->ast(), Node\Stmt\ClassLike::class) as $class) {
            if (! $class instanceof Node\Stmt\ClassLike || ! isset($class->namespacedName)) {
                continue;
            }

            $owner = $class->namespacedName->toString();

            foreach ($class->getProperties() as $property) {
                $name = $this->classNameFor($property->type, $owner);

                if ($name === null) {
                    continue;
                }

                foreach ($property->props as $declared) {
                    $this->properties[self::key($owner, $declared->name->toString())] = $name;
                }
            }

            // `public function __construct( private Cache $cache )` declares a
            // property in the parameter list, and it is the modern spelling of
            // exactly the shape this exists for.
            $constructor = $class->getMethod('__construct');

            if ($constructor === null) {
                continue;
            }

            $this->observeConstructions($class, $owner);

            foreach ($constructor->params as $param) {
                $name = $this->classNameFor($param->type, $owner);

                if ($name === null || $param->flags === 0 || ! $param->var instanceof Node\Expr\Variable) {
                    continue;
                }

                $variable = $param->var->name;

                if (is_string($variable)) {
                    $this->properties[self::key($owner, $variable)] = $name;
                }
            }
        }
    }

    /**
     * `$this->db = new DB()`, anywhere in the class.
     *
     * Most WordPress plugins predate typed properties and spell it this way, so
     * without this the index knows the return type of `code_snippets()` and
     * still cannot get from `Plugin` to `Plugin::$db`. {@see ClassTypeMap} sees
     * the same assignment but only while analysing the body it appears in,
     * which is almost never the body doing the reading.
     */
    private function observeConstructions(Node\Stmt\ClassLike $class, string $owner): void
    {
        foreach ((new NodeFinder())->findInstanceOf($class, Node\Expr\Assign::class) as $assign) {
            if (
                ! $assign instanceof Node\Expr\Assign
                || ! $assign->var instanceof Node\Expr\PropertyFetch
                || ! $assign->expr instanceof Node\Expr\New_
                || ! $assign->var->name instanceof Node\Identifier
                || ! $assign->expr->class instanceof Node\Name
            ) {
                continue;
            }

            $key = self::key($owner, $assign->var->name->toString());
            $class_ = $this->resolveOwnReference($assign->expr->class->toString(), $owner);

            if ($class_ === null || isset($this->ambiguous[$key])) {
                continue;
            }

            if (isset($this->properties[$key]) && $this->properties[$key] !== $class_) {
                unset($this->properties[$key]);
                $this->ambiguous[$key] = true;

                continue;
            }

            $this->properties[$key] = $class_;
        }
    }

    /**
     * Record a function's declared return class.
     */
    public function observeFunction(FunctionContext $context): void
    {
        $class = ClassTypeMap::declaredClassName($context->func->returnType);

        if ($class !== null) {
            $this->returns[$context->key] = $class;
        }
    }

    public function returnClassOf(string $functionKey): ?string
    {
        return $this->returns[strtolower($functionKey)] ?? null;
    }

    /**
     * The declared class of a property, following inheritance.
     *
     * A `protected DB $db` declared on a base class is read through the
     * subclass everywhere the loader pattern appears, and a flat lookup under
     * the subclass's name missed it. The walk tries the owner, its traits,
     * then the parents, in PHP's own precedence order.
     */
    public function propertyClassOf(?string $ownerClass, string $property): ?string
    {
        if ($ownerClass === null) {
            return null;
        }

        foreach ($this->hierarchy->lookupOrder($ownerClass) as $candidate) {
            $declared = $this->properties[strtolower($candidate) . '::' . $property] ?? null;

            if ($declared !== null) {
                return $declared;
            }
        }

        return null;
    }

    private function classNameFor(?Node $type, string $owner): ?string
    {
        if ($type instanceof Node\NullableType) {
            return $this->classNameFor($type->type, $owner);
        }

        if (! $type instanceof Node\Name) {
            return null;
        }

        return $this->resolveOwnReference($type->toString(), $owner);
    }

    /**
     * `self` is the declaring class and `parent` is one up the hierarchy —
     * `private static ?self $instance` is how every singleton in the ecosystem
     * spells its own type. `static` stays unresolved: as a type it is only
     * legal on returns, where php-cfg handles it. A scalar is not a class at
     * all. php-parser spells all of these as a Name once a type is written
     * without a leading backslash.
     */
    private function resolveOwnReference(string $name, string $owner): ?string
    {
        $lowered = strtolower($name);

        if ($lowered === 'self') {
            return $owner;
        }

        if ($lowered === 'parent') {
            return $this->hierarchy->parentOf($owner);
        }

        return in_array($lowered, self::NOT_A_CLASS, true) ? null : $name;
    }

    private const NOT_A_CLASS = [
        'self', 'static', 'parent', 'string', 'int', 'float', 'bool', 'array',
        'callable', 'iterable', 'object', 'mixed', 'void', 'never', 'null', 'false', 'true',
    ];

    private static function key(string $class, string $property): string
    {
        return strtolower(ltrim($class, '\\')) . '::' . $property;
    }
}
