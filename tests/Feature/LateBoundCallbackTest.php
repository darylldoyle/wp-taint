<?php

declare(strict_types=1);

// `$this` in a method of a base class is whatever class the object really is.
// A base that registers `array( $this, 'render' )` runs a subclass's override
// when the subclass is constructed, so the callback resolves to the base's body
// and to every override the scan declared.

it('follows a callback registered by a parent into the child override', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Base {
            public function __construct() { add_action( 'acme_x', [ $this, 'render' ] ); }
            public function render( $v ) { echo esc_html( $v ); }
        }
        class Acme_Child extends Acme_Base {
            public function render( $v ) { echo $v; }
        }
        new Acme_Child();
        function acme_fire() { do_action( 'acme_x', $_GET['b'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@7']);
    expect($result->findings->all()[0]->severity->value)->toBe('high');
});

it('follows the override at any depth and skips a subclass that does not override', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Base {
            public function __construct() { add_action( 'acme_x', [ $this, 'render' ] ); }
            public function render( $v ) { echo esc_html( $v ); }
        }
        class Acme_Middle extends Acme_Base {}
        class Acme_Leaf extends Acme_Middle {
            public function render( $v ) { echo $v; }
        }
        class Acme_Other_Leaf extends Acme_Middle {}
        function acme_fire() { do_action( 'acme_x', $_GET['b'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@8']);
});

it('resolves a callback on an abstract method to its overrides', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        abstract class Acme_Base {
            public function __construct() { add_filter( 'acme_label', [ $this, 'label' ] ); }
            abstract public function label( $v );
        }
        class Acme_Child extends Acme_Base {
            public function label( $v ) { return $_GET['b']; }
        }
        function acme_show() { echo apply_filters( 'acme_label', 'A safe default' ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@9']);
});

it('follows a callback a trait registers into the using class', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        trait Acme_Registers {
            public function register() { add_action( 'acme_x', [ $this, 'render' ] ); }
        }
        class Acme_Widget {
            use Acme_Registers;
            public function render( $v ) { echo $v; }
        }
        function acme_fire() { do_action( 'acme_x', $_GET['b'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@7']);
});

it('treats a static callback as late-bound too', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Base {
            public static function boot() { add_action( 'acme_x', array( 'static', 'render' ) ); }
            public static function render( $v ) { echo esc_html( $v ); }
        }
        class Acme_Child extends Acme_Base {
            public static function render( $v ) { echo $v; }
        }
        function acme_fire() { do_action( 'acme_x', $_GET['b'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@7']);
});

it('follows a late-bound callable through an ordinary dispatcher', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Base {
            public function run() { call_user_func( [ $this, 'render' ], $_GET['b'] ); }
            public function render( $v ) { echo esc_html( $v ); }
        }
        class Acme_Child extends Acme_Base {
            public function render( $v ) { echo $v; }
        }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.xss.unescaped-output@7']);
});

it('does not widen a receiver whose class is known exactly', function (): void {
    // `new Acme_Base()` is an Acme_Base, never a subclass.
    $result = scanCode(<<<'PHP'
        <?php
        class Acme_Base {
            public function render( $v ) { echo esc_html( $v ); }
        }
        class Acme_Child extends Acme_Base {
            public function render( $v ) { echo $v; }
        }
        function acme_boot() {
            $base = new Acme_Base();
            add_action( 'acme_x', [ $base, 'render' ] );
        }
        function acme_fire() { do_action( 'acme_x', $_GET['b'] ); }
        PHP);

    expect(findingSignatures($result))->toBe(['wp.output.unescaped-unknown@6']);
});
