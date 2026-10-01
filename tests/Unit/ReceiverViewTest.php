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

it('marks the union of two bodies that called or held different things', function (): void {
    $applied = new ReceiverView([], ['acme::add' => ['acme::add', [], 'acme::add']]);
    $waiting = new ReceiverView([], ['acme::add' => ['acme::add', [], null]]);
    $other = new ReceiverView([], ['acme::clear' => ['acme::clear', [], 'acme::clear']]);
    $one = new ReceiverView([], [], ['sub' => 'acme_query@a.php:3']);
    $none = new ReceiverView([], [], ['sub' => null]);

    expect($applied->union($applied)->opaque)->toBeFalse()
        ->and($applied->union($waiting)->opaque)->toBeTrue()
        ->and($applied->union($other)->opaque)->toBeFalse()
        ->and(array_keys($applied->union($other)->calls))->toBe(['acme::add', 'acme::clear'])
        ->and($one->union($one)->opaque)->toBeFalse()
        ->and($one->union($none)->opaque)->toBeTrue()
        ->and($one->union(new ReceiverView())->allocations)->toBe(['sub' => 'acme_query@a.php:3']);
});

it('keeps the write flag of either body in the union', function (): void {
    $wrote = new ReceiverView(writes: true);

    expect($wrote->union(new ReceiverView())->writes)->toBeTrue()
        ->and((new ReceiverView())->union($wrote)->writes)->toBeTrue()
        ->and((new ReceiverView())->union(new ReceiverView())->writes)->toBeFalse();
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
