<?php

declare(strict_types=1);

use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Taint\Provenance;
use Enshrined\WpTaint\Taint\Shape;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

it('starts empty, and a clean part makes nothing', function (): void {
    expect(Shape::empty()->isEmpty())->toBeTrue()
        ->and(Shape::of(TaintSet::empty())->isEmpty())->toBeTrue()
        ->and(Shape::element('title', Shape::empty())->isEmpty())->toBeTrue()
        ->and(Shape::rest(Shape::empty())->isEmpty())->toBeTrue();
});

it('keeps an element under its literal key apart from the rest', function (): void {
    $html = TaintSet::of(TaintKind::Html);
    $sql = TaintSet::of(TaintKind::Sql);

    $shape = Shape::element('title', Shape::of($html))->join(Shape::rest(Shape::of($sql)));

    expect($shape->elementAt('title')->flatten()->toStrings())->toBe(['html'])
        ->and($shape->elementAt('id')->isEmpty())->toBeTrue()
        ->and($shape->restPart()->flatten()->toStrings())->toBe(['sql'])
        ->and($shape->flatten()->toStrings())->toBe(['html', 'sql'])
        ->and($shape->elementsFlattened()->toStrings())->toBe(['html']);
});

it('treats a numeric string key as the int PHP stores it as', function (): void {
    $shape = Shape::element('0', Shape::of(TaintSet::of(TaintKind::Html)));

    expect(array_keys($shape->elements()))->toBe([0])
        ->and($shape->elementAt(0)->flatten()->toStrings())->toBe(['html']);
});

it('joins element by element and compares by value', function (): void {
    $html = TaintSet::of(TaintKind::Html);
    $sql = TaintSet::of(TaintKind::Sql);

    $a = Shape::element('k', Shape::of($html));
    $b = Shape::element('k', Shape::of($sql))->join(Shape::element('j', Shape::of($html)));
    $joined = $a->join($b);

    expect($joined->elementAt('k')->flatten()->toStrings())->toBe(['html', 'sql'])
        ->and($joined->elementAt('j')->flatten()->toStrings())->toBe(['html'])
        ->and($joined->equals($b->join($a)))->toBeTrue()
        ->and($joined->equals($a))->toBeFalse()
        ->and($a->join(Shape::empty()))->toBe($a);
});

it('folds a part deeper than the limit into its node', function (): void {
    // One level is what the per-key slots kept: `$a['x']` holds a flat set,
    // so what was under `'x'`'s own keys is merged into it.
    $inner = Shape::element('y', Shape::of(TaintSet::of(TaintKind::Html)))
        ->join(Shape::element('z', Shape::of(TaintSet::of(TaintKind::Sql))));
    $outer = Shape::element('x', $inner);

    expect(Shape::DEPTH)->toBe(1)
        ->and($outer->elementAt('x')->elements())->toBe([])
        ->and($outer->elementAt('x')->own()->toStrings())->toBe(['html', 'sql']);
});

it('cuts a shape to a given depth without losing taint', function (): void {
    $shape = Shape::element('x', Shape::of(TaintSet::of(TaintKind::Html)))
        ->join(Shape::rest(Shape::of(TaintSet::of(TaintKind::Sql))));

    $leaf = $shape->cut(0);

    expect($leaf->elements())->toBe([])
        ->and($leaf->restPart()->isEmpty())->toBeTrue()
        ->and($leaf->own()->toStrings())->toBe(['html', 'sql'])
        ->and($shape->cut(1)->equals($shape))->toBeTrue();
});

it('keeps the write behind a part until a later write adds to its taint', function (): void {
    $first = new Provenance(TraceVerb::Propagate, null, 'first');
    $second = new Provenance(TraceVerb::Propagate, null, 'second');
    $html = TaintSet::of(TaintKind::Html);

    $shape = Shape::element('k', Shape::of($html, $first));
    $same = $shape->join(Shape::element('k', Shape::of($html, $second)));
    $more = $shape->join(Shape::element('k', Shape::of(TaintSet::of(TaintKind::Sql), $second)));

    expect($same->elementAt('k')->provenance())->toBe($first)
        ->and($more->elementAt('k')->provenance())->toBe($second)
        ->and($more->elementAt('k')->flatten()->toStrings())->toBe(['html', 'sql']);
});

it('names a write only for the parts that name none', function (): void {
    $first = new Provenance(TraceVerb::Propagate, null, 'first');
    $write = new Provenance(TraceVerb::Propagate, null, 'write');

    $shape = Shape::element('a', Shape::of(TaintSet::of(TaintKind::Html), $first))
        ->join(Shape::element('b', Shape::of(TaintSet::of(TaintKind::Sql))))
        ->withProvenance($write);

    expect($shape->elementAt('a')->provenance())->toBe($first)
        ->and($shape->elementAt('b')->provenance())->toBe($write)
        ->and($shape->provenance())->toBeNull();
});
