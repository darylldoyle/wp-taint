<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\ConstantReturnTable;

it('folds a templated return through its parameter segments', function (): void {
    $table = new ConstantReturnTable();
    $table->recordTemplate('wc_helper::get_view_filename', ['/plugin/views', '/', 0]);

    expect($table->templateFor('WC_Helper::get_view_filename'))->toBe(['/plugin/views', '/', 0]);
    expect($table->templateForUniqueMethod('get_view_filename'))->toBe(['/plugin/views', '/', 0]);
});

it('refuses a method name two classes declare', function (): void {
    $table = new ConstantReturnTable();
    $table->recordTemplate('a::view', ['/a/', 0]);
    $table->recordTemplate('b::view', ['/b/', 0]);

    expect($table->templateForUniqueMethod('view'))->toBeNull();
    expect($table->templateFor('a::view'))->toBe(['/a/', 0]);
});
