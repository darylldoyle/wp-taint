<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use Enshrined\WpTaint\Taint\TaintState;
use PHPCfg\Operand\Temporary;

// The detection behind the non-convergence invariant. A debug run turns change
// counting on, and the operand that flips value far more than the rest is the
// one two ops cannot agree on — the disease every historical non-convergence
// shared. FunctionAnalysis reads this to name the culprit and, under
// WP_TAINT_DEBUG, throw instead of warn.

it('counts nothing until change counting is turned on', function (): void {
    $state = new TaintState();
    $operand = new Temporary();

    $state->set($operand, TaintSet::of(TaintKind::Html));
    $state->set($operand, TaintSet::empty());

    expect($state->oscillators(1))->toBe([]);
});

it('reports an operand that keeps flipping value, worst first', function (): void {
    $state = new TaintState();
    $state->countChanges();

    $calm = new Temporary();
    $wild = new Temporary();

    // $calm settles after one change; $wild flips back and forth.
    $state->set($calm, TaintSet::of(TaintKind::Html));
    $state->set($calm, TaintSet::of(TaintKind::Html));

    for ($round = 0; $round < 10; $round++) {
        $state->set($wild, $round % 2 === 0 ? TaintSet::of(TaintKind::Sql) : TaintSet::empty());
    }

    $oscillators = $state->oscillators(5);

    expect($oscillators)->toHaveCount(1);
    expect($oscillators[0]['operand'])->toBe($wild);
    expect($oscillators[0]['changes'])->toBe(10);
});

it('does not flag a value that never actually changes', function (): void {
    $state = new TaintState();
    $state->countChanges();
    $operand = new Temporary();

    for ($round = 0; $round < 20; $round++) {
        $state->set($operand, TaintSet::of(TaintKind::Sql));
    }

    // Set 20 times, changed once: the same value is not oscillation.
    expect($state->oscillators(2))->toBe([]);
});
