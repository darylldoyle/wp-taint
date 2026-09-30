<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
use Enshrined\WpTaint\Cfg\ConstantTable;
use Enshrined\WpTaint\Taint\UserFunctionTable;

// An allocation site's key names the class the run is on only when the
// method with the `new` runs on objects of more than one class.

function allocationSiteTableFor(string $code): UserFunctionTable
{
    $result = (new CfgBuilder('/tmp'))->build($code, '/tmp/allocation-site-snippet.php');
    $table = new UserFunctionTable();
    $table->addFile($result->file());

    return $table;
}

it('names a method that runs on one class only as such', function (): void {
    $table = allocationSiteTableFor(<<<'PHP'
        <?php
        trait Solo_Queries { function init() {} }
        class Solo { use Solo_Queries; function make() {} }
        PHP);

    expect($table->runsOnSeveralClasses('solo', 'make'))->toBeFalse();
    expect($table->runsOnSeveralClasses('solo_queries', 'init'))->toBeFalse();
});

it('names a trait method two classes use and an inherited method as running on several', function (): void {
    $table = allocationSiteTableFor(<<<'PHP'
        <?php
        trait Shared_Queries { function init() {} }
        class Orders { use Shared_Queries; }
        class Taxes { use Shared_Queries; }
        class Report { function make() {} function own() {} }
        class Stats_Report extends Report { function own() {} }
        PHP);

    expect($table->runsOnSeveralClasses('shared_queries', 'init'))->toBeTrue();
    expect($table->runsOnSeveralClasses('report', 'make'))->toBeTrue();
    expect($table->runsOnSeveralClasses('report', 'own'))->toBeFalse();
});

it('adds the class to a site key and takes it off again', function (): void {
    $site = ConstantTable::allocationSite('Acme\\Query', 'src/a:b.php', 7);
    $key = ConstantTable::siteFor($site, '\\Acme\\Orders');

    expect($key)->toBe('acme\\query@src/a:b.php:7^acme\\orders');
    expect(ConstantTable::holderOf($key))->toBe('acme\\orders');
    expect(ConstantTable::unqualifiedSite($key))->toBe($site);
    expect(ConstantTable::allocatedClass($key))->toBe('acme\\query');
    expect(ConstantTable::holderOf($site))->toBeNull();
    expect(ConstantTable::unqualifiedSite($site))->toBe($site);
    expect(ConstantTable::holderOf('acme\\orders#run'))->toBeNull();
});
