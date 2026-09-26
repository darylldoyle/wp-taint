<?php

declare(strict_types=1);

use Enshrined\WpTaint\Hooks\HookGraph;
use Enshrined\WpTaint\Hooks\HookRegistration;
use Enshrined\WpTaint\Taint\CallTarget;

function hookRegistration(
    string $hook,
    string $callback,
    string $file,
    int $line,
    int $priority = 10,
): HookRegistration {
    $target = CallTarget::resolved([], null, $callback, $callback . '()');

    return new HookRegistration($hook, $target, $file, $line, $priority);
}

/**
 * The order the lookups gave before they were cached: usort on the sort key.
 *
 * @param list<HookRegistration> $registrations
 *
 * @return list<string>
 */
function sortedCallbacks(array $registrations): array
{
    usort(
        $registrations,
        static fn (HookRegistration $a, HookRegistration $b): int => $a->sortKey() <=> $b->sortKey(),
    );

    return array_map(static fn (HookRegistration $r): string => (string) $r->callback->userFunctionKey, $registrations);
}

/**
 * @param list<HookRegistration|CallTarget> $items
 *
 * @return list<string>
 */
function callbackKeys(array $items): array
{
    return array_map(
        static fn (HookRegistration|CallTarget $item): string => (string) (
            $item instanceof HookRegistration ? $item->callback : $item
        )->userFunctionKey,
        $items,
    );
}

it('orders a hook\'s callbacks exactly as sorting on the sort key does, and keeps doing so', function (): void {
    $registrations = [
        hookRegistration('save_post', 'late', 'b.php', 9, 20),
        hookRegistration('save_post', 'early', 'z.php', 1, 5),
        hookRegistration('save_post', 'same_priority_b', 'b.php', 3),
        hookRegistration('save_post', 'same_priority_a', 'a.php', 7),
    ];
    $graph = new HookGraph();

    foreach ($registrations as $registration) {
        $graph->add($registration);
    }

    expect(callbackKeys($graph->callbacksFor('save_post')))->toBe(sortedCallbacks($registrations));
    expect(callbackKeys($graph->callbacksFor('save_post')))->toBe(sortedCallbacks($registrations));
});

it('forgets a remembered answer when a registration arrives', function (): void {
    $graph = new HookGraph();
    $first = hookRegistration('save_post', 'first', 'a.php', 1);
    $graph->add($first);

    expect(callbackKeys($graph->callbacksFor('save_post')))->toBe(['first']);

    $second = hookRegistration('save_post', 'second', 'a.php', 2, 1);
    $graph->add($second);

    expect(callbackKeys($graph->callbacksFor('save_post')))->toBe(sortedCallbacks([$first, $second]));
});

it('matches a computed hook name by prefix as before, and sees hooks added later', function (): void {
    $graph = new HookGraph();
    $page = hookRegistration('save_post_page', 'on_page', 'p.php', 4);
    $product = hookRegistration('save_post_product', 'on_product', 'q.php', 2, 5);
    $graph->add($page);
    $graph->add($product);

    expect(callbackKeys($graph->targetsMatchingPrefix('save_post_')))->toBe(sortedCallbacks([$page, $product]));

    $book = hookRegistration('save_post_book', 'on_book', 'r.php', 8);
    $graph->add($book);

    expect(callbackKeys($graph->targetsMatchingPrefix('save_post_')))->toBe(sortedCallbacks([$page, $product, $book]));
});

it('joins a literal dispatch to prefix registrations as before, and sees ones added later', function (): void {
    $graph = new HookGraph();
    $dynamic = hookRegistration('save_post_', 'on_any_type', 'd.php', 3);

    expect($graph->addPrefix($dynamic))->toBeTrue();
    expect(callbackKeys($graph->prefixTargetsFor('save_post_page')))->toBe(['on_any_type']);

    $another = hookRegistration('save_post_pa', 'on_pa', 'e.php', 1, 1);
    $graph->addPrefix($another);

    expect(callbackKeys($graph->prefixTargetsFor('save_post_page')))->toBe(sortedCallbacks([$dynamic, $another]));
});
