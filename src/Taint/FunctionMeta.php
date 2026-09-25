<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;

/**
 * What the rest of the scan needs to know about a function without its body.
 *
 * Every question one function's analysis asks about another is answered here:
 * its key, its name, its class, and its parameters' names and by-reference
 * flags. The body itself, the control flow graph the analysis runs on, comes
 * from {@see FunctionBodies}, which can rebuild it from source. Keeping the two
 * apart is what lets a scan drop a graph it will not need again.
 *
 * `position` locates the body in its file: null for the file's top-level code,
 * otherwise its index among the file's functions. Building the same file again
 * produces the same functions in the same order, so the position finds the
 * same body.
 */
final class FunctionMeta
{
    /**
     * @param list<array{name: string|null, byRef: bool, variadic: bool}> $parameters
     */
    public function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $displayName,
        public readonly ?string $className,
        public readonly string $path,
        public readonly string $relativePath,
        public readonly ?int $position,
        public readonly bool $isMain,
        public readonly bool $isClosure,
        public readonly array $parameters,
    ) {
    }

    public static function of(FunctionContext $context, ?int $position): self
    {
        $parameters = [];

        foreach (array_values($context->func->params) as $parameter) {
            $parameters[] = $parameter instanceof Op\Expr\Param
                ? [
                    'name' => OperandHelper::literalString($parameter->name),
                    'byRef' => $parameter->byRef,
                    'variadic' => $parameter->variadic,
                ]
                : ['name' => null, 'byRef' => false, 'variadic' => false];
        }

        return new self(
            $context->key,
            $context->func->name,
            $context->displayName,
            $context->className,
            $context->file->path,
            $context->file->relativePath,
            $position,
            $context->isMain(),
            $context->isClosure(),
            $parameters,
        );
    }

    /**
     * The same spelling {@see FunctionContext::parameterName()} gives.
     */
    public function parameterName(int $index): string
    {
        $name = $this->parameters[$index]['name'] ?? null;

        return $name === null ? '$' . $index : '$' . $name;
    }
}
