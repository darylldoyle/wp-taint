<?php

declare(strict_types=1);

// A filter's result always carries the value handed in. The scan cannot know
// which callbacks are on a hook when it fires: a registration can sit behind a
// condition, `remove_filter()` can take it off, and code outside the scan can
// add or remove callbacks. So a callback that sanitises is never credited, and
// a callback that introduces taint still adds it on top.

it('does not credit a sanitiser registered as a filter callback', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'esc_html' );
        function acme_show() { echo apply_filters( 'acme_label', $_GET['a'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
    expect($result->findings->all()[0]->severity->value)->toBe('high');
});

it('does not credit a user callback that escapes', function (string $dispatch): void {
    $result = scanCode(<<<PHP
        <?php
        add_filter( 'acme_label', 'acme_escape_label' );
        function acme_escape_label( \$v ) { return esc_html( \$v ); }
        function acme_show() { echo {$dispatch}; }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@4']);
})->with([
    'apply_filters' => ["apply_filters( 'acme_label', \$_GET['a'] )"],
    'apply_filters_ref_array' => ["apply_filters_ref_array( 'acme_label', array( \$_GET['a'] ) )"],
]);

it('traces the finding through the filter, not through the callback', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'esc_html' );
        function acme_show() { echo apply_filters( 'acme_label', $_GET['a'] ); }
        PHP);

    $verbs = array_map(
        static fn (object $step): string => $step->verb->value,
        $result->findings->all()[0]->trace,
    );

    expect($verbs)->toBe(['source', 'propagate', 'sink']);
});

it('still adds the taint a filter callback introduces', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'acme_inject' );
        function acme_inject( $v ) { return $_GET['a']; }
        function acme_show() { echo apply_filters( 'acme_label', 'A safe default' ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@4']);
});

it('reports escaping undone by a filter even when a callback is registered', function (): void {
    // Before, a registered callback replaced the filter's own semantics, so this
    // was silent while the same line with nothing on the hook was reported.
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'acme_keep' );
        function acme_keep( $v ) { return $v; }
        function acme_show() { echo apply_filters( 'acme_label', esc_html( $_GET['a'] ) ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.escape-voided@4']);
});

it('does not claim escaping was voided when no single path escaped and filtered', function (): void {
    // The callback escapes a value of its own. The pass-through carries the
    // voiding marker and the callback carries the escaped one. Neither path did
    // both, so there is nothing to report, as at a branch merge.
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'acme_own_label' );
        function acme_own_label( $v ) { return esc_html( get_option( 'acme_label' ) ); }
        function acme_show() { echo apply_filters( 'acme_label', '' ); }
        PHP);

    expect($result->findings)->toBeEmpty();
});

it('is satisfied by escaping after the filter', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        add_filter( 'acme_label', 'acme_inject' );
        function acme_inject( $v ) { return $_GET['b']; }
        function acme_show() { echo esc_html( apply_filters( 'acme_label', $_GET['a'] ) ); }
        PHP);

    expect($result->findings)->toBeEmpty();
});

it('still credits a sanitiser that an ordinary dispatcher calls', function (string $code): void {
    // call_user_func() and array_map() run the callable they are handed and
    // nothing else, so the callee's return is the dispatcher's return.
    expect(scanCode($code)->findings)->toBeEmpty();
})->with([
    'call_user_func' => [<<<'PHP'
        <?php
        function acme_show() { echo call_user_func( 'esc_html', $_GET['a'] ); }
        PHP],
    'call_user_func_array' => [<<<'PHP'
        <?php
        function acme_show() { echo call_user_func_array( 'esc_html', array( $_GET['a'] ) ); }
        PHP],
    'array_map' => [<<<'PHP'
        <?php
        function acme_show() {
            foreach ( array_map( 'esc_html', (array) $_GET['a'] ) as $v ) { echo $v; }
        }
        PHP],
]);
