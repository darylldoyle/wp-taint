<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\FunctionSummary;
use Enshrined\WpTaint\Taint\Shape;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;

/**
 * A summary whose parameter 0 reaches one property, one capture and one
 * included file's variable, each with the given kinds.
 */
function summaryReaching(TaintSet $kinds): FunctionSummary
{
    return new FunctionSummary(
        'acme_fn',
        'acme_fn()',
        paramToProperty: [0 => [['Acme_Box', 'v', Shape::of($kinds)]]],
        paramToCapture: [0 => [['closure#1', 'label', $kinds]]],
        paramToScope: [0 => [['in', 'tpl.php::{main}', 'label', Shape::of($kinds)]]],
    );
}

it('keeps one reference per place when two bodies merge, with the kinds of both', function (): void {
    $merged = summaryReaching(TaintSet::of(TaintKind::Sql))
        ->union(summaryReaching(TaintSet::of(TaintKind::Html)));

    $both = TaintSet::of(TaintKind::Sql, TaintKind::Html);

    expect($merged->propertiesFor(0))->toHaveCount(1)
        ->and($merged->propertiesFor(0)[0][2]->flatten()->equals($both))->toBeTrue()
        ->and($merged->capturesFor(0))->toHaveCount(1)
        ->and($merged->capturesFor(0)[0][2]->equals($both))->toBeTrue()
        ->and($merged->scopesFor(0))->toHaveCount(1)
        ->and($merged->scopesFor(0)[0][3]->flatten()->equals($both))->toBeTrue();
});

it('is not settled while the kinds reaching a place are still growing', function (): void {
    $sql = summaryReaching(TaintSet::of(TaintKind::Sql));

    expect($sql->equals(summaryReaching(TaintSet::of(TaintKind::Sql))))->toBeTrue()
        ->and($sql->equals(summaryReaching(TaintSet::of(TaintKind::Sql, TaintKind::Html))))->toBeFalse();
});
