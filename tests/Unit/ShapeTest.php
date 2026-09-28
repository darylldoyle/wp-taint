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

it('keeps nested elements apart down to the limit, and folds what is deeper', function (): void {
    $inner = Shape::element('y', Shape::of(TaintSet::of(TaintKind::Html)))
        ->join(Shape::element('z', Shape::of(TaintSet::of(TaintKind::Sql))));
    $outer = Shape::element('x', $inner);

    expect(Shape::DEPTH)->toBe(4)
        ->and($outer->elementAt('x')->elementAt('y')->flatten()->toStrings())->toBe(['html'])
        ->and($outer->elementAt('x')->elementAt('z')->flatten()->toStrings())->toBe(['sql']);

    // Five levels: the fourth keeps its taint and loses its parts.
    $deep = Shape::element('e', $inner);

    foreach (['d', 'c', 'b', 'a'] as $key) {
        $deep = Shape::element($key, $deep);
    }

    $fourth = $deep->elementAt('a')->elementAt('b')->elementAt('c')->elementAt('d');

    expect($fourth->elements())->toBe([])
        ->and($fourth->own()->toStrings())->toBe(['html', 'sql']);
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

it('names a write for the parts that carry taint and name none', function (): void {
    $first = new Provenance(TraceVerb::Propagate, null, 'first');
    $write = new Provenance(TraceVerb::Propagate, null, 'write');

    $shape = Shape::element('a', Shape::of(TaintSet::of(TaintKind::Html), $first))
        ->join(Shape::element('b', Shape::of(TaintSet::of(TaintKind::Sql))))
        ->withProvenance($write);

    // The array itself holds no taint of its own, but its parts do, so it
    // names the write that put them there.
    expect($shape->elementAt('a')->provenance())->toBe($first)
        ->and($shape->elementAt('b')->provenance())->toBe($write)
        ->and($shape->provenance())->toBe($write)
        ->and(Shape::empty()->withProvenance($write)->provenance())->toBeNull();
});

it('takes kinds out of every part and drops a part left clean', function (): void {
    $shape = Shape::element('a', Shape::of(TaintSet::of(TaintKind::Escaped)))
        ->join(Shape::element('b', Shape::of(TaintSet::of(TaintKind::Escaped, TaintKind::Html))))
        ->join(Shape::rest(Shape::of(TaintSet::of(TaintKind::Escaped))));

    $without = $shape->without(TaintSet::of(TaintKind::Escaped));

    expect(array_keys($without->elements()))->toBe(['b'])
        ->and($without->elementAt('b')->flatten()->toStrings())->toBe(['html'])
        ->and($without->restPart()->isEmpty())->toBeTrue()
        ->and($shape->without(TaintSet::of(TaintKind::Sql)))->toBe($shape);
});
