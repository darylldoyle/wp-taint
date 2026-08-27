<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * One analysable function body, with everything the analyser needs about where
 * it came from.
 */
final class FunctionContext
{
    public function __construct(
        public readonly ParsedFile $file,
        public readonly Func $func,
        public readonly string $key,
        public readonly string $displayName,
        public readonly ?string $className,
    ) {
    }

    /**
     * Lookup key: lowercase, `class::method` for methods, the fully-qualified
     * name for functions, `file::{main}` for top-level code.
     */
    public static function keyFor(Func $func, ParsedFile $file): string
    {
        $class = $func->class?->value;

        if (is_string($class) && $class !== '') {
            return strtolower($class . '::' . $func->name);
        }

        if ($func->name === '{main}') {
            return strtolower($file->relativePath . '::{main}');
        }

        if (str_starts_with($func->name, '{anonymous}')) {
            return strtolower($file->relativePath . '::' . $func->name);
        }

        return strtolower($func->name);
    }

    public static function create(Func $func, ParsedFile $file): self
    {
        $class = $func->class?->value;
        $className = is_string($class) && $class !== '' ? $class : null;

        $display = $className !== null
            ? $className . '::' . $func->name
            : $func->name;

        return new self($file, $func, self::keyFor($func, $file), $display, $className);
    }

    public function isMain(): bool
    {
        return $this->func->name === '{main}';
    }

    public function isClosure(): bool
    {
        return ($this->func->flags & Func::FLAG_CLOSURE) !== 0;
    }

    /**
     * `Func` carries no source position of its own; the declaring op does.
     */
    public function declarationOp(): ?Op
    {
        return $this->func->callableOp instanceof Op ? $this->func->callableOp : null;
    }

    public function parameterName(int $index): string
    {
        $param = $this->func->params[$index] ?? null;

        if ($param === null) {
            return '$' . $index;
        }

        $name = OperandHelper::literalString($param->name);

        return $name === null ? '$' . $index : '$' . $name;
    }

    public function parameterCount(): int
    {
        return count($this->func->params);
    }

    /**
     * Indexes of the parameters declared `&$x`.
     *
     * A by-reference parameter is the callee's half of a write the caller can
     * see. php-cfg records the flag on the `Param` op; what it does not do is
     * connect the write back to the caller's operand, which is what
     * {@see FunctionSummary::$paramToParam} exists for.
     *
     * @return list<int>
     */
    public function byRefParameters(): array
    {
        $indexes = [];

        foreach (array_values($this->func->params) as $index => $param) {
            if ($param instanceof Op\Expr\Param && $param->byRef) {
                $indexes[] = $index;
            }
        }

        return $indexes;
    }

    /**
     * The operand a by-reference parameter writes through.
     */
    public function parameterOperand(int $index): ?Operand
    {
        $param = $this->func->params[$index] ?? null;

        return $param instanceof Op\Expr\Param ? $param->result : null;
    }
}
