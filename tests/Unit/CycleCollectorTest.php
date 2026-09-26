<?php

declare(strict_types=1);

use Enshrined\WpTaint\Support\CycleCollector;

it('turns the automatic collector off for its run and restores it after', function (): void {
    gc_enable();
    $collector = new CycleCollector();

    $collector->start();
    expect(gc_enabled())->toBeFalse();

    $collector->stop();
    expect(gc_enabled())->toBeTrue();
});

it('leaves the automatic collector off when it was off before', function (): void {
    gc_disable();
    $collector = new CycleCollector();

    try {
        $collector->start();
        $collector->stop();
        expect(gc_enabled())->toBeFalse();
    } finally {
        gc_enable();
    }
});

it('collects the cycles a tick finds once the heap has grown by its step', function (): void {
    $collector = new CycleCollector(1024 * 1024);
    $collector->start();

    try {
        $before = gc_status()['runs'];

        for ($i = 0; $i < 20_000; $i++) {
            $a = new stdClass();
            $a->self = $a;
            $a->padding = str_repeat('x', 100);
            unset($a);
        }

        $collector->tick();

        expect(gc_status()['runs'])->toBeGreaterThan($before);
    } finally {
        $collector->stop();
    }
});
