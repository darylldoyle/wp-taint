<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Taint\ClassHierarchy;

function hierarchyFor(string $code): ClassHierarchy
{
    $result = (new CfgBuilder('/tmp'))->build($code, '/tmp/hierarchy-snippet.php');
    $hierarchy = new ClassHierarchy();
    $hierarchy->observeFile($result->file());

    return $hierarchy;
}

it('records who extends whom, lowercased', function (): void {
    $hierarchy = hierarchyFor('<?php class A {} class B extends A {}');

    expect($hierarchy->parentOf('B'))->toBe('a');
    expect($hierarchy->parentOf('b'))->toBe('a');
    expect($hierarchy->parentOf('A'))->toBeNull();
});

it('walks the class, its traits, then the parent and its traits', function (): void {
    $hierarchy = hierarchyFor(<<<'PHP'
        <?php
        trait ParentTrait {}
        trait ChildTrait {}
        class Base { use ParentTrait; }
        class Child extends Base { use ChildTrait; }
        PHP);

    expect($hierarchy->lookupOrder('Child'))
        ->toBe(['child', 'childtrait', 'base', 'parenttrait']);
});

it('expands a trait used by a trait, in place', function (): void {
    $hierarchy = hierarchyFor(<<<'PHP'
        <?php
        trait Inner {}
        trait Outer { use Inner; }
        class Uses { use Outer; }
        PHP);

    expect($hierarchy->lookupOrder('Uses'))->toBe(['uses', 'outer', 'inner']);
});

it('starts with the class itself even when nothing else is known', function (): void {
    $hierarchy = hierarchyFor('<?php class Lone {}');

    expect($hierarchy->lookupOrder('Lone'))->toBe(['lone']);
    expect($hierarchy->lookupOrder('never_declared'))->toBe(['never_declared']);
});

it('ends the walk at a parent the scan never saw declared', function (): void {
    $hierarchy = hierarchyFor('<?php class Table extends WP_List_Table {}');

    // The unknown parent is still *named* — the walk tries it and stops there,
    // because nothing records what WP_List_Table extends.
    expect($hierarchy->lookupOrder('Table'))->toBe(['table', 'wp_list_table']);
});

it('survives a cyclic extends chain in broken code', function (): void {
    $hierarchy = hierarchyFor('<?php class X extends Y {} class Y extends X {}');

    expect($hierarchy->lookupOrder('X'))->toBe(['x', 'y']);
});

it('lets the first declaration of a duplicate class win', function (): void {
    $hierarchy = hierarchyFor(<<<'PHP'
        <?php
        trait FirstTrait {}
        trait SecondTrait {}
        class Dup extends A { use FirstTrait; }
        class Dup extends B { use SecondTrait; }
        class A {}
        class B {}
        PHP);

    expect($hierarchy->parentOf('Dup'))->toBe('a');
    expect($hierarchy->lookupOrder('Dup'))->toBe(['dup', 'firsttrait', 'a']);
});

it('resolves namespaced names the way the resolver spells them', function (): void {
    $hierarchy = hierarchyFor(<<<'PHP'
        <?php
        namespace Acme;

        class Base {}
        class Child extends Base {}
        PHP);

    expect($hierarchy->parentOf('Acme\Child'))->toBe('acme\base');
    expect($hierarchy->lookupOrder('acme\child'))->toBe(['acme\child', 'acme\base']);
});
