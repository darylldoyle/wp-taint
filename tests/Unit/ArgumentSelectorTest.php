<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\ArgumentSelector;

it('matches everything when unrestricted', function (): void {
    $selector = ArgumentSelector::all();

    expect($selector->matchesEverything())->toBeTrue();
    expect($selector->contains(7))->toBeTrue();
    expect($selector->resolve(3))->toBe([0, 1, 2]);
});

it('resolves a single index', function (): void {
    expect(ArgumentSelector::index(1)->resolve(4))->toBe([1]);
    expect(ArgumentSelector::index(1)->contains(0))->toBeFalse();
});

it('drops indexes beyond the actual argument count', function (): void {
    expect(ArgumentSelector::indexes([0, 5])->resolve(2))->toBe([0]);
});

it('sorts indexes so output order is stable', function (): void {
    expect(ArgumentSelector::indexes([3, 1, 2])->describe())->toBe('1,2,3');
});

it('resolves to nothing for a call with no arguments', function (): void {
    expect(ArgumentSelector::index(0)->resolve(0))->toBe([]);
    expect(ArgumentSelector::all()->resolve(0))->toBe([0]);
});
