<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * GraphViz dot output of the taint graph.
 *
 * This is the debugging tool you reach for every time a finding looks wrong or
 * a finding you expected is missing. It exists from the start rather than being
 * bolted on later, because the alternative is reading SSA dumps by eye.
 *
 *   wp-taint scan ./src --dump-taint-graph=taint.dot
 *   dot -Tsvg taint.dot -o taint.svg
 */
final class TaintGraphWriter
{
    /** @var list<string> */
    private array $lines = [];

    /** @var SplObjectStorage<Operand, string> */
    private SplObjectStorage $ids;

    private int $nextId = 0;

    public function __construct()
    {
        $this->ids = new SplObjectStorage();
    }

    public function addFunction(FunctionContext $context, TaintState $state): void
    {
        $body = [];

        foreach (BlockOrder::of($context->func->cfg) as $block) {
            foreach ([...$block->phi, ...$block->children] as $op) {
                if (! $op instanceof Op) {
                    continue;
                }

                foreach (OperandHelper::operandsOf($op) as $operand) {
                    $taint = $state->taintOf($operand);

                    if ($taint->isEmpty()) {
                        continue;
                    }

                    $body[] = $this->node($operand, $taint, $state, $context);

                    $provenance = $state->provenanceOf($operand);

                    foreach ($provenance === null ? [] : $provenance->predecessors as $predecessor) {
                        if ($state->taintOf($predecessor)->isEmpty()) {
                            continue;
                        }

                        $body[] = sprintf(
                            '    %s -> %s [label=%s];',
                            $this->idFor($predecessor),
                            $this->idFor($operand),
                            self::quote($provenance?->verb->value ?? 'propagate'),
                        );
                    }
                }
            }
        }

        if ($body === []) {
            return;
        }

        $this->lines[] = sprintf('  subgraph %s {', self::quote('cluster_' . $this->nextId++));
        $label = $context->displayName . ' — ' . $context->file->relativePath;

        $this->lines[] = sprintf('    label=%s;', self::quote($label));
        $this->lines[] = '    style=rounded; color="#999999";';
        $this->lines = [...$this->lines, ...array_values(array_unique($body))];
        $this->lines[] = '  }';
    }

    private function node(Operand $operand, TaintSet $taint, TaintState $state, FunctionContext $context): string
    {
        $provenance = $state->provenanceOf($operand);
        $position = OperandHelper::position($provenance?->op, $context->file->sourceMap);

        $label = sprintf(
            "%s\\n%s%s",
            OperandHelper::describe($operand),
            $taint->describe(),
            $position['line'] > 0 ? "\\n:" . $position['line'] : '',
        );

        return sprintf(
            '    %s [label=%s, shape=box, style=filled, fillcolor=%s];',
            $this->idFor($operand),
            self::quote($label),
            self::quote(self::colourFor($provenance)),
        );
    }

    private static function colourFor(?Provenance $provenance): string
    {
        return match ($provenance?->verb->value) {
            'source' => '#ffd9d9',
            'sanitize' => '#d9ffd9',
            'sink' => '#ff9999',
            'call', 'return' => '#d9e6ff',
            default => '#f2f2f2',
        };
    }

    private function idFor(Operand $operand): string
    {
        if (! $this->ids->contains($operand)) {
            $this->ids[$operand] = 'n' . spl_object_id($operand);
        }

        return $this->ids[$operand];
    }

    public function render(): string
    {
        return "digraph taint {\n"
            . "  rankdir=LR;\n"
            . "  node [fontname=\"monospace\", fontsize=10];\n"
            . "  edge [fontname=\"monospace\", fontsize=9, color=\"#666666\"];\n"
            . implode("\n", $this->lines)
            . "\n}\n";
    }

    private static function quote(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }
}
