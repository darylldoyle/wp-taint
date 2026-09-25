<?php

declare(strict_types=1);

// A strict in_array() against a literal list proves the value is one of those
// literals. The list is usually held in a variable, and only a list written
// inline counted, so the ordinary spelling of an allowlist was not credited.

it('credits an allowlist held in a variable', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_set() {
            $name = $_POST['setting_name'];
            $allowed = array( 'blogname', 'blogdescription' );
            if ( ! in_array( $name, $allowed, true ) ) { return; }
            update_option( $name, 'x' );
            echo $name;
        }
        PHP);

    expect($result->findings->all())->toBe([]);
});

it('still does not credit a loose in_array()', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_set() {
            $name = $_POST['setting_name'];
            $allowed = array( 'blogname', 'blogdescription' );
            if ( ! in_array( $name, $allowed ) ) { return; }
            echo $name;
        }
        PHP);

    expect(array_map(static fn ($f): string => $f->ruleId, $result->findings->all()))
        ->toBe(['wp.xss.unescaped-output']);
});
