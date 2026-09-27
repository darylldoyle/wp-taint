<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\CallGraph;

/**
 * A handler, a helper it calls, and a filter callback its helper dispatches,
 * with the only check in the callback.
 */
function graphWithCheckInHookCallback(): CallGraph
{
    $graph = new CallGraph();

    foreach (['handler', 'helper', 'callback'] as $key) {
        $graph->addFunction($key);
    }

    $graph->addEdge('handler', 'helper');
    $graph->addEdge('helper', 'callback', viaHook: true);
    $graph->addExternal('callback', 'current_user_can');

    return $graph;
}

it('does not credit a check that only a hook callback makes', function (): void {
    $graph = graphWithCheckInHookCallback();

    expect($graph->reaches('handler', ['current_user_can']))->toBeFalse()
        ->and($graph->walkWasComplete('handler', ['current_user_can']))->toBeTrue();
});

it('still gives a hook callback a caller and a place in the call order', function (): void {
    $graph = graphWithCheckInHookCallback();

    expect($graph->hasCaller('callback'))->toBeTrue()
        ->and($graph->calleesOf('helper'))->toBe(['callback']);
});

it('credits a function the caller also calls by name, whichever edge came first', function (): void {
    $hookFirst = graphWithCheckInHookCallback();
    $hookFirst->addEdge('helper', 'callback');

    $directFirst = new CallGraph();
    $directFirst->addEdge('handler', 'helper');
    $directFirst->addEdge('helper', 'callback');
    $directFirst->addEdge('helper', 'callback', viaHook: true);
    $directFirst->addExternal('callback', 'current_user_can');

    expect($hookFirst->reaches('handler', ['current_user_can']))->toBeTrue()
        ->and($directFirst->reaches('handler', ['current_user_can']))->toBeTrue()
        ->and($hookFirst->calleesOf('helper'))->toBe(['callback']);
});

it('reaches a callback through another route that calls it directly', function (): void {
    $graph = graphWithCheckInHookCallback();
    $graph->addFunction('other');
    $graph->addEdge('handler', 'other');
    $graph->addEdge('other', 'callback');

    expect($graph->reaches('handler', ['current_user_can']))->toBeTrue();
});
