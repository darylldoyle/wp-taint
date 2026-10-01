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

/**
 * A shape three levels deep with one part shared under ten keys at each
 * level: 1,000 paths to its leaf, and four distinct parts.
 */
function sharedShape(): Shape
{
    $level = Shape::of(TaintSet::of(TaintKind::Html));

    for ($depth = 0; $depth < 3; $depth++) {
        $next = Shape::empty();

        for ($key = 0; $key < 10; $key++) {
            $next = $next->join(Shape::element('k' . $key, $level));
        }

        $level = $next;
    }

    return $level;
}

/**
 * How many distinct part objects a shape is made of.
 */
function distinctParts(Shape $shape, array &$seen = []): int
{
    $seen[spl_object_id($shape)] = true;

    foreach ($shape->elements() as $element) {
        distinctParts($element, $seen);
    }

    if (! $shape->restPart()->isEmpty()) {
        distinctParts($shape->restPart(), $seen);
    }

    return count($seen);
}

it('keeps a part shared under many keys shared when it rebuilds the shape', function (): void {
    // Each rebuild once copied every path to a shared part. Four levels
    // sharing under ten keys made 10,000 copies of the leaf, and a whole-site
    // scan ran out of 20GB copying one returned array this way.
    $shape = sharedShape();
    $write = new Provenance(TraceVerb::Propagate, null, 'write');

    expect(distinctParts($shape))->toBe(4);

    $named = $shape->withProvenance($write);

    expect(distinctParts($named))->toBe(4)
        ->and($named->elementAt('k0'))->toBe($named->elementAt('k9'))
        ->and($named->elementAt('k3')->elementAt('k5')->elementAt('k7')->provenance())->toBe($write)
        ->and($named->equals($shape))->toBeTrue();

    $mapped = $shape->mapSets(static fn (TaintSet $kinds): TaintSet => $kinds->with(TaintKind::Sql));

    expect(distinctParts($mapped))->toBe(4)
        ->and($mapped->elementAt('k2')->elementAt('k4')->elementAt('k6')->flatten()->toStrings())
        ->toBe(['html', 'sql']);

    expect(distinctParts(Shape::element('top', $shape)))->toBe(5)
        ->and(distinctParts($shape->cut(1)))->toBe(2)
        ->and(distinctParts($named->without(TaintSet::of(TaintKind::Html))))->toBe(1);
});

it('hands back a shape whose every part already names its write', function (): void {
    $first = new Provenance(TraceVerb::Propagate, null, 'first');
    $named = sharedShape()->withProvenance($first);

    expect($named->withProvenance(new Provenance(TraceVerb::Propagate, null, 'second')))->toBe($named)
        ->and($named->cut(Shape::DEPTH))->toBe($named);
});

/**
 * A shape with `$width` elements under each of three levels, each leaf a
 * different kind under a different key: `$width` cubed paths, none shared.
 */
function wideShape(int $width): Shape
{
    $shape = Shape::empty();

    for ($a = 0; $a < $width; $a++) {
        for ($b = 0; $b < $width; $b++) {
            for ($c = 0; $c < $width; $c++) {
                $kind = ($a + $b + $c) % 2 === 0 ? TaintKind::Html : TaintKind::Sql;
                $leaf = Shape::element('c' . $c, Shape::of(TaintSet::of($kind)));
                $shape = $shape->join(Shape::element('a' . $a, Shape::element('b' . $b, $leaf)));
            }
        }
    }

    return $shape->join(Shape::element('a0', Shape::keys(TaintSet::of(TaintKind::Path))));
}

it('counts a part once for each path to it, and stops counting past the cap', function (): void {
    expect(sharedShape()->paths())->toBe(1 + 10 + 100 + 1000)
        ->and(Shape::empty()->paths())->toBe(1)
        ->and(wideShape(22)->paths())->toBe(Shape::MAX_PATHS + 1);
});

it('leaves a shape within the cap as it is', function (): void {
    $shape = wideShape(3);

    expect($shape->bounded())->toBe($shape)
        ->and($shape->joinBounded(wideShape(3)))->toBe($shape);
});

it('folds a shape past the cap into its rest, keeping every kind at every depth', function (): void {
    // 22 cubed is 10,648 leaves, past the cap of 10,000.
    $write = new Provenance(TraceVerb::Propagate, null, 'write');
    $shape = wideShape(22)->withProvenance($write);
    $folded = $shape->bounded();

    expect($folded->paths())->toBeLessThan(10)
        ->and($folded->elements())->toBe([])
        ->and($folded->flatten()->toStrings())->toBe($shape->flatten()->toStrings())
        ->and($folded->restPart()->own()->toStrings())->toEqualCanonicalizing(['html', 'path', 'sql'])
        ->and($folded->restPart()->restPart()->restPart()->own()->toStrings())
        ->toEqualCanonicalizing(['html', 'path', 'sql'])
        ->and($folded->keysTaint()->toStrings())->toBe(['path'])
        ->and($folded->restPart()->keysTaint()->toStrings())->toBe(['path'])
        ->and($folded->restPart()->provenance())->toBe($write);
});

it('hands back the stored shape when a fold adds nothing, so a round can settle', function (): void {
    $stored = Shape::empty()->joinBounded(wideShape(22));

    expect($stored->paths())->toBeLessThan(10)
        ->and($stored->joinBounded(wideShape(22)))->toBe($stored);

    // A small shape keeps its keys beside the fold, once.
    $grown = $stored->joinBounded(wideShape(2));

    expect($grown->elementAt('a1')->elementAt('b1')->elementAt('c0')->flatten()->toStrings())->toBe(['html'])
        ->and($grown->joinBounded(wideShape(2)))->toBe($grown)
        ->and($grown->joinBounded(wideShape(22)))->toBe($grown);
});
