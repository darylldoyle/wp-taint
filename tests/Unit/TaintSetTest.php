<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

it('starts empty', function (): void {
    expect(TaintSet::empty()->isEmpty())->toBeTrue();
    expect(TaintSet::empty()->kinds())->toBe([]);
    expect(TaintSet::empty()->describe())->toBe('(none)');
});

it('unions and intersects', function (): void {
    $html = TaintSet::of(TaintKind::Html);
    $sql = TaintSet::of(TaintKind::Sql);

    expect($html->union($sql)->toStrings())->toBe(['html', 'sql']);
    expect($html->union($sql)->intersect($sql)->toStrings())->toBe(['sql']);
    expect($html->intersect($sql)->isEmpty())->toBeTrue();
});

it('clears specific kinds and leaves the rest', function (): void {
    // The single most important modelling decision in the project: esc_html()
    // clears HTML and does nothing at all for SQL.
    $set = TaintSet::of(TaintKind::Html, TaintKind::HtmlAttr, TaintKind::Sql);
    $cleared = $set->clear(TaintKind::Html);

    expect($cleared->has(TaintKind::Html))->toBeFalse();
    expect($cleared->has(TaintKind::Sql))->toBeTrue();
    expect($cleared->has(TaintKind::HtmlAttr))->toBeTrue();
});

it('clears everything for an integer cast', function (): void {
    expect(TaintSet::allDataflowKinds()->clearAll()->isEmpty())->toBeTrue();
});

it('excludes the authz category from the dataflow kinds', function (): void {
    // Authz is a finding category, not a taint kind. Nothing seeds it and
    // nothing propagates it.
    expect(TaintSet::allDataflowKinds()->has(TaintKind::Authz))->toBeFalse();

    foreach (TaintKind::dataflowKinds() as $kind) {
        expect(TaintSet::allDataflowKinds()->has($kind))->toBeTrue();
    }
});

it('compares by value', function (): void {
    expect(TaintSet::of(TaintKind::Html, TaintKind::Sql)->equals(TaintSet::of(TaintKind::Sql, TaintKind::Html)))
        ->toBeTrue();
    expect(TaintSet::of(TaintKind::Html)->equals(TaintSet::of(TaintKind::Sql)))->toBeFalse();
});

it('reports subset relationships', function (): void {
    expect(TaintSet::of(TaintKind::Html)->isSubsetOf(TaintSet::allDataflowKinds()))->toBeTrue();
    expect(TaintSet::allDataflowKinds()->isSubsetOf(TaintSet::of(TaintKind::Html)))->toBeFalse();
    expect(TaintSet::empty()->isSubsetOf(TaintSet::empty()))->toBeTrue();
});

it('renders kinds in declaration order regardless of construction order', function (): void {
    // Byte-identical output across runs depends on this.
    $a = TaintSet::of(TaintKind::Sql, TaintKind::Html, TaintKind::Url);
    $b = TaintSet::of(TaintKind::Url, TaintKind::Sql, TaintKind::Html);

    expect($a->toStrings())->toBe($b->toStrings());
    expect($a->toStrings())->toBe(['html', 'sql', 'url']);
});

it('builds from strings and rejects unknown kinds', function (): void {
    expect(TaintSet::fromStrings(['html', 'sql'])->toStrings())->toBe(['html', 'sql']);

    expect(static fn (): TaintSet => TaintSet::fromStrings(['not_a_kind']))
        ->toThrow(InvalidArgumentException::class, 'Unknown taint kind "not_a_kind"');
});

it('is immutable', function (): void {
    $original = TaintSet::of(TaintKind::Html);
    $original->clear(TaintKind::Html);
    $original->with(TaintKind::Sql);

    expect($original->toStrings())->toBe(['html']);
});

it('gives every kind a distinct bit', function (): void {
    $bits = array_map(static fn (TaintKind $kind): int => $kind->bit(), TaintKind::cases());

    expect(count(array_unique($bits)))->toBe(count($bits));
});
