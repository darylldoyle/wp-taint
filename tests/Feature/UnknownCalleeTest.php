<?php

declare(strict_types=1);

use Enshrined\WpTaint\Taint\AnalysisOptions;
use Enshrined\WpTaint\Taint\DynamicCallPolicy;

// A callee the engine cannot name may do more than return a value. It may
// store its arguments in its object, and it may write back through any argument
// it takes by reference. Only the first was assumed, so a value that came back
// out any other way was silent.

/** @return list<string> */
function unknownCalleeRules(string $code, DynamicCallPolicy $policy = DynamicCallPolicy::Propagate): array
{
    return array_map(
        static fn ($finding): string => $finding->ruleId . ' ' . $finding->severity->value,
        scanCode($code, new AnalysisOptions(dynamicCalls: $policy))->findings->all(),
    );
}

it('assumes an unknown callee can write back through a variable passed to it', function (): void {
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        function acme_run( $cb ) { $out = ''; $cb( $_GET['a'], $out ); echo $out; }
        PHP))->toBe(['wp.xss.unescaped-output high']);
});

it('assumes an unknown method can store its argument in its object and return it later', function (): void {
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        function acme_run( $box, $m ) { $box->$m( $_GET['a'] ); echo $box->get(); }
        PHP))->toBe(['wp.xss.unescaped-output high']);
});

it('still assumes an unknown callee returns what it was given', function (): void {
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        function acme_run( $cb ) { echo $cb( $_GET['a'] ); }
        PHP))->toBe(['wp.xss.unescaped-output high']);
});

it('writes nothing back when the arguments carry nothing', function (): void {
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        function acme_run( $cb ) { $label = 'Hello'; $cb( esc_html( $_GET['a'] ), $label ); echo esc_html( $label ); }
        PHP))->toBe([]);
});

it('assumes no write-back when unknown callees are assumed clean', function (): void {
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        function acme_run( $cb ) { $out = ''; $cb( $_GET['a'], $out ); echo $out; }
        PHP, DynamicCallPolicy::Clean))->toBe([]);
});

it('writes back only through what a computed name on a known class could name', function (): void {
    // `$this->{ 'validate_' . $type }( … )` is one of the class's validate_*
    // methods, and none of them takes $setting by reference.
    expect(unknownCalleeRules(<<<'PHP'
        <?php
        class Acme_Settings {
            public function validate_text( $value, $setting ) { return sanitize_text_field( $value ); }
            public function validate_number( $value, $setting ) { return (int) $value; }
            public function update( $type ) {
                $setting = array( 'option_key' => 'acme_option' );
                $value = $this->{ 'validate_' . $type }( $_POST['value'], $setting );
                update_option( $setting['option_key'], $value );
            }
        }
        PHP))->toBe([]);
});
