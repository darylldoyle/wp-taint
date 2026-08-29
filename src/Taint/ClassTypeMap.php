<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * The little bit of type inference method call resolution needs.
 *
 * Deliberately shallow: `new Foo()` assigned to a variable, a parameter with a
 * declared class type, and properties assigned from either. Anything beyond
 * that is left unresolved rather than guessed, because a wrong class turns into
 * a wrong sink match and a critical-severity false positive.
 */
final class ClassTypeMap
{
    /** @var SplObjectStorage<Operand, string> */
    private SplObjectStorage $operandClasses;

    /** @var array<string, string> */
    private array $propertyClasses = [];

    public function __construct()
    {
        $this->operandClasses = new SplObjectStorage();
    }

    public function classOf(Operand $operand): ?string
    {
        if (! $this->operandClasses->contains($operand)) {
            return null;
        }

        return $this->operandClasses[$operand];
    }

    public function classOfProperty(?string $ownerClass, string $property): ?string
    {
        return $this->propertyClasses[strtolower(($ownerClass ?? '?') . '::' . $property)] ?? null;
    }

    public function setClass(Operand $operand, string $class): void
    {
        $this->operandClasses[$operand] = $class;
    }

    public function setPropertyClass(?string $ownerClass, string $property, string $class): void
    {
        $this->propertyClasses[strtolower(($ownerClass ?? '?') . '::' . $property)] = $class;
    }

    /**
     * Seed from parameter type declarations, then from the function body.
     */
    public function seedFromFunction(FunctionContext $context): void
    {
        foreach ($context->func->params as $param) {
            if (! $param instanceof Op\Expr\Param) {
                continue;
            }

            $class = self::declaredClassName($param->declaredType);

            if ($class === null) {
                continue;
            }

            $this->setClass($param->result, $class);
        }
    }

    /**
     * Record `$x = new Foo()` and `$this->x = new Foo()`.
     */
    public function observe(Op $op, ?string $enclosingClass): void
    {
        if (! $op instanceof Op\Expr\Assign) {
            return;
        }

        $source = OperandHelper::definingOp($op->expr);

        if (! $source instanceof Op\Expr\New_) {
            return;
        }

        $class = OperandHelper::literalString($source->class);

        if ($class === null) {
            return;
        }

        $this->setClass($op->var, $class);
        $this->setClass($op->result, $class);

        $target = OperandHelper::definingOp($op->var);

        if ($target instanceof Op\Expr\PropertyFetch) {
            $property = OperandHelper::literalString($target->name);

            if ($property !== null) {
                $this->setPropertyClass($enclosingClass, $property, $class);
            }
        }
    }

    /**
     * Public because {@see DeclaredTypes} reads return types the same way, and
     * two spellings of "what class does this declaration name" that could drift
     * apart is exactly the disagreement that made receiver resolution wrong in
     * the first place.
     */
    public static function declaredClassName(Op\Type $type): ?string
    {
        if ($type instanceof Op\Type\Reference) {
            $name = OperandHelper::literalString($type->declaration);

            return $name === '' ? null : $name;
        }

        if ($type instanceof Op\Type\Nullable) {
            return self::declaredClassName($type->subtype);
        }

        return null;
    }

    /**
     * Every function is analysed more than once (summary extraction, then
     * finding collection), and the operand identities are stable across those
     * runs, so the map is reusable.
     */
    public static function forFunction(FunctionContext $context, Func $func): self
    {
        $map = new self();
        $map->seedFromFunction($context);

        unset($func);

        return $map;
    }
}
