<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Finding\TraceVerb;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * How an operand came to be tainted.
 *
 * Provenance is what makes traces possible, and traces are what make findings
 * actionable. Walking these links backwards from a sink reconstructs the path
 * to the source.
 */
final class Provenance
{
    /**
     * @param list<Operand> $predecessors operands this taint flowed from, in
     *                                    source order; the trace picks the
     *                                    first one carrying the kind being
     *                                    traced
     */
    public function __construct(
        public readonly TraceVerb $verb,
        public readonly ?Op $op,
        public readonly string $description,
        public readonly array $predecessors = [],
        public readonly ?string $callee = null,
        public readonly ?int $parameterIndex = null,
        public readonly bool $imprecise = false,
    ) {
    }
}
