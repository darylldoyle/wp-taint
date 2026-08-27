<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Registry\Registry;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Answers "why was this *not* flagged?"
 *
 * The primary risk with a tool like this is false negatives, and a false
 * negative is invisible by construction. This turns "I don't trust it" into a
 * specific, checkable statement about what the engine did and did not do at a
 * given line.
 *
 * Three answers matter:
 *
 * 1. Taint reached here and a sanitizer cleared it — names the sanitizer.
 * 2. No source ever reached here — names where the value did come from.
 * 3. A path was abandoned at something the engine could not resolve — names it,
 *    which is the answer that actually changes a reviewer's mind.
 */
final class Explainer
{
    public function __construct(
        private readonly Registry $registry,
        private readonly CallResolver $resolver,
        private readonly IntraproceduralAnalyzer $analyzer,
        private readonly AnalysisOptions $options,
    ) {
    }

    /**
     * @param list<FunctionContext> $contexts
     */
    public function explain(
        ParsedFile $file,
        int $line,
        array $contexts,
        SummaryTable $summaries,
        PropertyTaintMap $properties,
        ScopeTable $scopes,
        ?TaintKind $kind,
    ): Explanation {
        $observations = [];
        $taint = TaintSet::empty();
        $found = false;

        foreach ($contexts as $context) {
            if ($context->file->relativePath !== $file->relativePath) {
                continue;
            }

            $result = $this->analyzer->analyze($context, $summaries, $properties, $scopes, null, false);
            $state = $result->state;

            if ($state === null) {
                continue;
            }

            $types = new ClassTypeMap();
            $types->seedFromFunction($context);

            foreach (BlockOrder::of($context->func->cfg) as $block) {
                foreach ($block->children as $op) {
                    if (! $op instanceof Op || $op->getLine() !== $line) {
                        continue;
                    }

                    $found = true;

                    foreach (OperandHelper::operandsOf($op) as $operand) {
                        $taint = $taint->union($state->taintOf($operand));
                    }

                    $observations = [
                        ...$observations,
                        ...$this->observeOperands($op, $context, $state, $types, $kind),
                    ];
                }
            }
        }

        return new Explanation(
            $file->relativePath,
            $line,
            trim($file->sourceMap->line($line)),
            $taint,
            $kind,
            $found,
            $this->deduplicate($observations),
        );
    }

    /**
     * @return list<string>
     */
    private function observeOperands(
        Op $op,
        FunctionContext $context,
        TaintState $state,
        ClassTypeMap $types,
        ?TaintKind $kind,
    ): array {
        $observations = [];

        foreach (OperandHelper::operandsOf($op) as $operand) {
            $provenance = $state->provenanceOf($operand);

            if ($provenance !== null) {
                // When the question is about a specific kind that is *absent*,
                // "assigned to $safe" is not an answer. Walk back and name the
                // sanitizer that cleared it.
                if ($kind !== null && ! $state->effectiveTaintOf($operand)->has($kind)) {
                    $cleared = $this->findSanitizer($operand, $state, 0);

                    if ($cleared !== null) {
                        $observations[] = 'sanitize: ' . $cleared;

                        continue;
                    }
                }

                $observations[] = sprintf('%s: %s', $provenance->verb->value, $provenance->description);

                continue;
            }

            $observations = [...$observations, ...$this->explainClean($operand, $context, $types, 0)];
        }

        return $observations;
    }

    /**
     * The nearest sanitize step upstream of an operand.
     */
    private function findSanitizer(Operand $operand, TaintState $state, int $depth): ?string
    {
        if ($depth > 24) {
            return null;
        }

        $provenance = $state->provenanceOf($operand);

        if ($provenance === null) {
            return null;
        }

        if ($provenance->verb === TraceVerb::Sanitize) {
            return $provenance->description;
        }

        foreach ($provenance->predecessors as $predecessor) {
            $found = $this->findSanitizer($predecessor, $state, $depth + 1);

            if ($found !== null) {
                return $found;
            }
        }

        return null;
    }

    /**
     * Walk backwards from a clean operand and say why it is clean.
     *
     * @return list<string>
     */
    private function explainClean(Operand $operand, FunctionContext $context, ClassTypeMap $types, int $depth): array
    {
        if ($depth > 12) {
            return [];
        }

        if ($operand instanceof Operand\Literal) {
            return [];
        }

        $definition = OperandHelper::definingOp($operand);

        if ($definition === null) {
            $name = OperandHelper::variableName($operand);

            if ($name === null) {
                return [];
            }

            return [sprintf('$%s has no definition in this function, so nothing is known about it.', $name)];
        }

        if ($definition instanceof Op\Expr\Assign) {
            return $this->explainClean($definition->expr, $context, $types, $depth + 1);
        }

        $target = $this->resolver->resolve($definition, $context, $types);

        if ($target === null) {
            return [];
        }

        if ($target->dynamic) {
            return [sprintf(
                'A potential path was abandoned: the call to %s could not be resolved (dynamic callee), '
                    . 'and --dynamic-calls=%s, so %s. '
                    . 'See KNOWN_LIMITATIONS.md § dynamic-calls, or re-run with --dynamic-calls=tainted.',
                $target->name(),
                $this->options->dynamicCalls->value,
                $this->options->dynamicCalls->describe(),
            )];
        }

        $matcher = $target->matcher;

        if ($matcher !== null) {
            $sanitizer = $this->registry->sanitizer($matcher);

            if ($sanitizer !== null) {
                return [sprintf(
                    '%s cleared %s before this point.',
                    $matcher->describe(),
                    $sanitizer->describeClears(),
                )];
            }

            if ($this->registry->knows($matcher)) {
                return [];
            }

            if ($target->userFunctionKey === null) {
                return [sprintf(
                    '%s is not in the catalogue, so its return value is treated as clean. If it should be a source, '
                        . 'add it to the registry under [[sources]].',
                    $matcher->describe(),
                )];
            }
        }

        return [];
    }

    /**
     * @param list<string> $observations
     *
     * @return list<string>
     */
    private function deduplicate(array $observations): array
    {
        $unique = [];

        foreach ($observations as $observation) {
            $unique[$observation] = true;
        }

        $result = array_keys($unique);
        sort($result);

        return $result;
    }
}
