<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;
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
