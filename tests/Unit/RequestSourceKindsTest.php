<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Matcher;
use Enshrined\WpTaint\Registry\Source;

// Request data is tainted in every context. The catalogue repeats that list on
// each source rather than naming it once, and the copies drifted: `object_id`
// and `csv` reached the superglobals and never reached the REST accessors, so
// `wp_delete_post( $request->get_param( 'id' ) )` was silent while the `$_GET`
// version was a high. These hold every whole-request source to `$_GET`'s kinds.

function requestKinds(?Source $source): array
{
    expect($source)->not->toBeNull();

    return $source?->kinds->toStrings() ?? [];
}

it('gives every request superglobal the same kinds', function (string $superglobal): void {
    $registry = testRegistry();

    expect(requestKinds($registry->source(Matcher::superglobal($superglobal))))
        ->toBe(requestKinds($registry->source(Matcher::superglobal('_GET'))));
})->with(['_POST', '_REQUEST', '_COOKIE']);

it('gives every REST parameter accessor the same kinds as $_GET', function (string $method): void {
    $registry = testRegistry();

    expect(requestKinds($registry->source(Matcher::method('WP_REST_Request', $method))))
        ->toBe(requestKinds($registry->source(Matcher::superglobal('_GET'))));
})->with(['get_param', 'get_params', 'get_json_params', 'get_query_params', 'get_body_params', 'get_body']);

it('gives the raw request body the same kinds as $_GET', function (): void {
    $registry = testRegistry();

    expect(requestKinds($registry->source(Matcher::function('file_get_contents'))))
        ->toBe(requestKinds($registry->source(Matcher::superglobal('_GET'))));
});

it('reports a REST parameter used as an object id', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_delete( WP_REST_Request $request ) {
            wp_delete_post( $request->get_param( 'id' ) );
        }
        PHP);

    expect(array_map(static fn ($finding): string => $finding->ruleId, $result->findings->all()))
        ->toContain('wp.authz.object-id-from-request');
});
