<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

use PHPCfg\Op;
use PHPCfg\Operand;
use SplObjectStorage;

/**
 * Is this string constrained — by a fixed fragment, or by construction we
 * cannot see?
 *
 * The question decides whether a request-controlled identifier is dangerous.
 * To set `default_role` an attacker needs the name to *be* `default_role`, and
 * any fixed fragment anywhere in it makes that impossible:
 *
 * ```php
 * update_option( $_POST['name'], $v );                 // names any option
 * update_option( 'acme_' . $_POST['k'], $v );          // names acme_*
 * update_option( $_POST['k'] . '_usage_optin', $v );   // names *_usage_optin
 * update_option( $this->slug . '_' . $key, $v );       // anchored by the '_'
 * ```
 *
 * Only the first is privilege escalation. The rest let an attacker create junk
 * in a namespace the plugin already owns, which is a much smaller problem and
 * the ordinary WordPress idiom for a per-entity option — present in most of the
 * corpus.
 *
 * ## Anywhere, not just the front
 *
 * This started out asking only about a literal *prefix*, which was wrong in a
 * way the corpus found immediately: `$source . '_usage_optin'` is anchored by
 * its tail and reported nine times in one plugin. Head, tail or middle, a fixed
 * fragment is a fixed fragment.
 *
 * ## It has to cross call boundaries, because the taint does
 *
 * The anchor is usually not where the write is. WooCommerce builds
 * `'woocommerce_onboarding_..._async_' . $job_id` in one method, hands it to a
 * constructor, stores it on a property and writes the option from a third — and
 * `$job_id` really is request data, so the taint reaching `update_option()` is
 * real and correctly traced. The prefix that makes it harmless is three frames
 * away.
 *
 * A purely local, syntactic check judges an interprocedural value and reports
 * every one of those. That was the entire false positive set this rule produced
 * across the corpus: 33 findings, essentially all of this shape.
 *
 * So a call is answered from its function summary and a property from what was
 * written to it, using the same machinery the taint itself travels on. What
 * neither can answer — an unresolvable callee, an untracked property — counts
 * as constrained, which is a documented false negative and the trade this
 * project makes everywhere else.
 */
final class LiteralAnchor
{
    private const MAX_DEPTH = 32;

    public function __construct(
        private readonly ?SummaryTable $summaries = null,
        private readonly ?CallResolver $resolver = null,
        private readonly ?PropertyTaintMap $properties = null,
        private readonly ?ReceiverResolver $receivers = null,
        private readonly ?FunctionContext $context = null,
        private readonly ?ClassTypeMap $types = null,
    ) {
    }

    public function has(Operand $operand): bool
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();

        return $this->check($operand, $seen, 0);
    }

    /**
     * The same question asked of a `return`, where a parameter proves nothing.
     *
     * Two different questions wear the same words. Reading a value, an unknown
     * parameter means "the caller anchored this, most likely" and counts as
     * constrained. Summarising a *return*, it means the opposite: `function f(
     * $id ) { return $id; }` guarantees its callers nothing, and calling that
     * anchored would launder the request through any one-line pass-through.
     *
     * `return 'acme_' . $id` is still anchored — the body supplies the literal.
     */
    public function hasWithinBody(Operand $operand): bool
    {
        /** @var SplObjectStorage<Operand, true> $seen */
        $seen = new SplObjectStorage();

        return $this->check($operand, $seen, 0, deferToCaller: false);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function check(Operand $operand, SplObjectStorage $seen, int $depth, bool $deferToCaller = true): bool
    {
        if ($depth > self::MAX_DEPTH || $seen->contains($operand)) {
            return false;
        }

        $seen->attach($operand);

        if ($operand instanceof Operand\Literal) {
            return ! is_string($operand->value) || $operand->value !== '';
        }

        $definition = OperandHelper::definingOp($operand);

        // Nothing defines it here, so it came from outside this function —
        // a parameter, most often. `new Acme( 'acme_' . $id )` anchors the name
        // the constructor stores, and nothing inside the constructor can see
        // that. Unknown counts as constrained, the same as an unresolvable
        // callee or an untracked property.
        return $definition === null ? true : $this->checkOp($definition, $seen, $depth, $deferToCaller);
    }

    /**
     * @param SplObjectStorage<Operand, true> $seen
     */
    private function checkOp(Op $definition, SplObjectStorage $seen, int $depth, bool $deferToCaller = true): bool
    {
        $recurse = fn (Operand $next): bool => $this->check($next, $seen, $depth + 1, $deferToCaller);

        return match (true) {
            $definition instanceof Op\Expr\ConstFetch,
            $definition instanceof Op\Expr\ClassConstFetch => true,
            $definition instanceof Op\Expr\FuncCall,
            $definition instanceof Op\Expr\NsFuncCall,
            $definition instanceof Op\Expr\MethodCall,
            $definition instanceof Op\Expr\StaticCall => $this->callIsAnchored($definition),
            $definition instanceof Op\Expr\PropertyFetch,
            $definition instanceof Op\Expr\StaticPropertyFetch => $this->propertyIsAnchored($definition),
            // A parameter's anchor belongs to the caller. `new Acme( 'acme_' .
            // $id )` anchors the name the constructor stores, and nothing
            // inside the constructor can see it.
            $definition instanceof Op\Expr\Param => $deferToCaller,
            $definition instanceof Op\Expr\Assign,
            $definition instanceof Op\Expr\AssignRef => $recurse($definition->expr),
            // Either side anchors the whole name.
            $definition instanceof Op\Expr\BinaryOp\Concat => $recurse($definition->left)
                || $recurse($definition->right),
            $definition instanceof Op\Expr\ConcatList => $this->any($definition->list, $recurse),
            // Every branch must be anchored, or one path through is not.
            $definition instanceof Op\Phi => $this->all($definition->vars, $recurse),
            default => false,
        };
    }

    /**
     * Does everything this callee can return carry a literal fragment?
     *
     * An unresolvable callee counts as anchored. We cannot see what it builds,
     * so we do not claim it builds nothing fixed.
     */
    private function callIsAnchored(Op\Expr $definition): bool
    {
        if ($this->summaries === null || $this->resolver === null || $this->context === null) {
            return true;
        }

        $call = $this->resolver->resolve($definition, $this->context, $this->types ?? new ClassTypeMap());
        $key = $call?->userFunctionKey;

        if ($key === null) {
            return true;
        }

        $summary = $this->summaries->get($key);

        return $summary === null || $summary->returnAnchored;
    }

    /**
     * Was every write to this property anchored?
     *
     * An untracked property counts as anchored, on the same reasoning.
     */
    private function propertyIsAnchored(Op\Expr $definition): bool
    {
        if ($this->properties === null || ! $definition instanceof Op\Expr\PropertyFetch) {
            return true;
        }

        $property = OperandHelper::literalString($definition->name);

        if ($property === null) {
            return true;
        }

        $class = $this->context === null
            ? null
            : $this->receivers?->classOf($definition->var, $this->context, $this->types ?? new ClassTypeMap());

        return $this->properties->isAnchored($class, $property);
    }

    /**
     * @param array<array-key, mixed>  $operands
     * @param callable(Operand): bool  $check
     */
    private function any(array $operands, callable $check): bool
    {
        foreach ($operands as $operand) {
            if ($operand instanceof Operand && $check($operand)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<array-key, mixed>  $operands
     * @param callable(Operand): bool  $check
     */
    private function all(array $operands, callable $check): bool
    {
        if ($operands === []) {
            return false;
        }

        foreach ($operands as $operand) {
            if (! $operand instanceof Operand || ! $check($operand)) {
                return false;
            }
        }

        return true;
    }
}
