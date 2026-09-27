<?php

declare(strict_types=1);

// A value held in an array's elements, and the trace that says where it came
// from. A propagator dropped an element written under a literal key, and a
// trace stopped at the first predecessor that led nowhere.

/**
 * @return list<array{rule: string, line: int, first: string}> each finding, with its trace's first step
 */
function elementTraceFindings(string $body): array
{
    return array_map(
        static fn ($finding): array => [
            'rule' => $finding->ruleId,
            'line' => $finding->line,
            'first' => $finding->trace[0]->verb->value . '@' . $finding->trace[0]->line,
        ],
        scanCode("<?php\n" . $body)->findings->all(),
    );
}

it('carries an element under a literal key through a propagator', function (): void {
    expect(elementTraceFindings(<<<'PHP'
        function acme_run() {
            $row = array( 'name' => $_GET['name'] );
            echo implode( ',', $row );
        }
        PHP))->toBe([['rule' => 'wp.xss.unescaped-output', 'line' => 4, 'first' => 'source@3']]);
});

it('traces an element back to its source through a propagator', function (): void {
    expect(elementTraceFindings(<<<'PHP'
        function acme_run() {
            $row = array( $_GET['name'] );
            echo implode( ',', $row );
        }
        PHP))->toBe([['rule' => 'wp.xss.unescaped-output', 'line' => 4, 'first' => 'source@3']]);
});

it('traces a value round a loop back to its source', function (): void {
    // The first predecessor of `$out . $_GET['v']` is `$out` from the last
    // time round, which the walk has already passed.
    expect(elementTraceFindings(<<<'PHP'
        function acme_run( $rows ) {
            $out = '';
            foreach ( $rows as $row ) {
                $out = $out . $_GET['v'];
            }
            echo $out;
        }
        PHP))->toBe([['rule' => 'wp.xss.unescaped-output', 'line' => 7, 'first' => 'source@5']]);
});

it('still traces an escaped value used unquoted back to its source', function (): void {
    expect(elementTraceFindings(<<<'PHP'
        function acme_run() {
            global $wpdb;
            $v = esc_sql( $_GET['v'] );
            $wpdb->query( "DELETE FROM t WHERE id = $v" );
        }
        PHP))->toBe([['rule' => 'wp.sqli.unprepared-query', 'line' => 5, 'first' => 'source@4']]);
});

it('gives a loop key the collection\'s own taint and none of its elements\'', function (): void {
    expect(elementTraceFindings(<<<'PHP'
        function acme_elements( $i ) {
            $rows = array();
            $rows[ $i ] = $_GET['x'];
            foreach ( $rows as $k => $v ) {
                echo '<label for="' . $k . '">';
            }
        }
        function acme_request() {
            foreach ( $_GET as $k => $v ) {
                echo '<label for="' . $k . '">';
            }
        }
        PHP))->toHaveCount(1)
        ->sequence(fn ($finding) => $finding->toMatchArray(['rule' => 'wp.xss.unescaped-output', 'line' => 11]));
});

it('starts a trace where a summary introduced the kind, not at the argument', function (): void {
    // sanitize_key() clears html, so the html the echo reports came from the
    // option acme_fields() returns. The trace used to walk on into $view and
    // name $_GET['view'] as its source.
    $html = array_values(array_filter(
        scanCode(<<<'PHP'
            <?php
            function acme_fields( $view ) {
                return array( 'label' => get_option( 'acme_label_' . $view ) );
            }
            function acme_page() {
                $view = sanitize_key( $_GET['view'] );
                foreach ( acme_fields( $view ) as $field ) {
                    echo $field;
                }
            }
            PHP)->findings->all(),
        static fn ($finding): bool => $finding->ruleId === 'wp.xss.unescaped-output',
    ));

    expect($html)->toHaveCount(1)
        ->and($html[0]->trace[0]->line)->toBe(7)
        ->and($html[0]->trace[0]->verb->value)->not->toBe('source');
});

it('keeps an element under its key through a function that keeps keys', function (): void {
    // array_filter() and apply_filters() return their input under the same
    // keys, so a stored 'value' must not taint the 'id' read beside it.
    expect(findingSignatures(scanCode(<<<'PHP'
        <?php
        function acme_run() {
            $field = array( 'id' => 'acme-field', 'value' => get_option( 'acme_value' ) );
            $field = apply_filters( 'acme_field', array_filter( $field ) );
            echo '<label for="' . $field['id'] . '">';
            echo '<input value="' . $field['value'] . '">';
        }
        PHP)))->toBe(['wp.xss.unescaped-output@6']);
});
