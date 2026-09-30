<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\ReceiverView;
use Enshrined\WpTaint\Taint\Shape;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

// What a method's own run read through `$this`, and when another receiver
// would see the same.

it('compares only the answers the run read', function (): void {
    $view = new ReceiverView(['defaults' => [ReceiverView::VALUE => Shape::empty()]]);

    // Another field class writes its defaults unanchored and tracks them
    // clean. The run read only the value, which is the same.
    expect($view->sawSame('defaults', [Shape::empty(), false, true]))->toBeTrue()
        ->and($view->sawSame('defaults', [Shape::of(TaintSet::of(TaintKind::Html)), true, null]))->toBeFalse();
});

it('compares the anchor and the tracked answer when the run read them', function (): void {
    $view = new ReceiverView([
        'table' => [ReceiverView::VALUE => Shape::empty(), ReceiverView::ANCHORED => true, ReceiverView::CLEAN => true],
    ]);

    expect($view->sawSame('table', [Shape::empty(), true, true]))->toBeTrue()
        ->and($view->sawSame('table', [Shape::empty(), false, true]))->toBeFalse()
        ->and($view->sawSame('table', [Shape::empty(), true, null]))->toBeFalse();
});

it('says nothing about a property the run did not read', function (): void {
    expect((new ReceiverView())->sawSame('limit', [Shape::empty(), true, null]))->toBeFalse();
});

it('answers for no other receiver after a copy of $this or a held-back write', function (): void {
    expect((new ReceiverView())->answersForOthers())->toBeTrue()
        ->and((new ReceiverView(opaque: true))->answersForOthers())->toBeFalse()
        ->and((new ReceiverView(writes: true))->answersForOthers())->toBeFalse()
        ->and((new ReceiverView(writes: true))->withWrites(false)->answersForOthers())->toBeTrue();
});

it('unions two bodies that saw the same, and marks two that did not', function (): void {
    $clean = new ReceiverView(['limit' => [ReceiverView::VALUE => Shape::empty()]]);
    $tainted = new ReceiverView(['limit' => [ReceiverView::VALUE => Shape::of(TaintSet::of(TaintKind::Sql))]]);
    $other = new ReceiverView(['where' => [ReceiverView::VALUE => Shape::empty()]]);

    expect($clean->union($clean)->opaque)->toBeFalse()
        ->and(array_keys($clean->union($other)->properties))->toBe(['limit', 'where'])
        ->and($clean->union($other)->opaque)->toBeFalse()
        ->and($clean->union($tainted)->opaque)->toBeTrue();
});

it('is equal only to a view of the same reads, calls and sites', function (): void {
    $view = new ReceiverView(
        ['limit' => [ReceiverView::VALUE => Shape::empty()]],
        ['acme::add' => ['acme::add', [], 'acme::add']],
        ['sub' => null],
    );

    expect($view->equals($view))->toBeTrue()
        ->and($view->equals(new ReceiverView(
            ['limit' => [ReceiverView::VALUE => Shape::empty()]],
            ['acme::add' => ['acme::add', [], 'acme::add']],
            ['sub' => null],
        )))->toBeTrue()
        ->and($view->equals(new ReceiverView(
            ['limit' => [ReceiverView::VALUE => Shape::empty()]],
            ['acme::add' => ['acme::add', [], null]],
            ['sub' => null],
        )))->toBeFalse()
        ->and($view->equals(null))->toBeFalse();
});
