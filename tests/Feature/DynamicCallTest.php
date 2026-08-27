<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\DynamicCallPolicy;

// Calls the engine has to see through.
//
// WordPress routes an enormous amount of control flow through a callable in a
// variable. An analyser that stops at the indirection stops exactly where the
// interesting flows are, so these are the shapes that have to resolve — and,
// just as importantly, the ones that must *not* resolve to a guess.

it('follows a callable through a dispatcher', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_render($value) { echo $value; }
        call_user_func('acme_render', $_GET['v']);
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@2']);
});

it('follows a callable that escapes, not only one that does not', function (): void {
    // The half that is easy to get wrong: resolving a dispatcher is only an
    // improvement if it can also prove a flow safe.
    $result = scanCode(<<<'PHP'
        <?php
        function acme_render($value) { echo esc_html($value); }
        call_user_func('acme_render', $_GET['v']);
        PHP);

    expect($result->findings)->toBeEmpty();
});

it('reaches every callee a callable variable can hold', function (): void {
    // Two names, one call site. Choosing one would be a guess, so both are
    // analysed and the effects unioned.
    $result = scanCode(<<<'PHP'
        <?php
        function acme_safe($v) { echo esc_html($v); }
        function acme_raw($v) { echo $v; }
        function acme_dispatch($mode) {
            $callback = $mode === 'safe' ? 'acme_safe' : 'acme_raw';
            $callback($_GET['v']);
        }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('resolves the array callable form through the receiver class', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Widget {
            public function render($value) { echo $value; }
            public function dispatch() {
                call_user_func(array($this, 'render'), $_GET['v']);
            }
        }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('resolves the class-name callable form as a static call', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Widget {
            public static function render($value) { echo $value; }
        }
        call_user_func(array('Acme_Widget', 'render'), $_GET['v']);
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('applies a named escaper passed to array_map', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        $safe = array_map('esc_html', $_GET['items']);
        echo implode(', ', $safe);
        PHP);

    expect($result->findings)->toBeEmpty();
});

it('does not launder taint through array_filter', function (): void {
    // array_filter() returns a subset of its input, not the predicate's
    // boolean. Treating the callee's return as the result would drop it.
    $result = scanCode(<<<'PHP'
        <?php
        $kept = array_filter($_GET['items'], 'strlen');
        echo implode(', ', $kept);
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('spreads a call_user_func_array argument array over the callee', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_render($value) { echo $value; }
        $args = array($_GET['v']);
        call_user_func_array('acme_render', $args);
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@2']);
});

it('leaves a name nobody can find a body for unresolved', function (): void {
    // The dangerous near-miss. Resolving 'acme_missing' to a function that
    // exists in neither the catalogue nor the scanned code, and then reporting
    // it clean, would lose the flow without even marking it imprecise.
    $result = scanCode(<<<'PHP'
        <?php
        echo call_user_func('acme_missing', $_GET['v']);
        PHP, new AnalysisOptions(dynamicCalls: DynamicCallPolicy::Clean));

    expect($result->findings)->toBeEmpty();

    $assumed = scanCode(<<<'PHP'
        <?php
        echo call_user_func('acme_missing', $_GET['v']);
        PHP);

    expect(findingSignatures($assumed))->toBe(['wp.xss.unescaped-output@2']);
    expect($assumed->findings->all()[0]->imprecise)->toBeTrue();
});

it('resolves a class name held in a variable at new', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Renderer {
            public function __construct($value) { echo $value; }
        }
        $class = 'Acme_Renderer';
        new $class($_GET['v']);
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@3']);
});

it('proves a flow safe only when every callee escapes it', function (): void {
    // The union has to cut both ways. Two callees that both escape leave
    // nothing behind; if the union were wrong, one sanitizer clearing the
    // other's result would silently hide the unsafe case above.
    $result = scanCode(<<<'PHP'
        <?php
        function acme_html($v) { echo esc_html($v); }
        function acme_attr($v) { echo esc_attr($v); }
        function acme_dispatch($mode) {
            $callback = $mode === 'attr' ? 'acme_attr' : 'acme_html';
            $callback($_GET['v']);
        }
        PHP);

    expect($result->findings)->toBeEmpty();
});
