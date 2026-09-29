<?php

declare(strict_types=1);

// An array function keeps what each element holds below itself: a function
// that keeps its input's keys or values keeps each element whole, one that
// returns an element keeps that element's parts, and `array_column()` reads
// only its column.

/**
 * @return list<string> rule@line for each finding
 */
function arrayFunctionFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps each element whole through a function that keeps keys', function (): void {
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show() {
            $row = array( 'meta' => array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            $merged = array_merge( array( 'id' => 7 ), $row );
            echo $merged['meta']['title'];
            echo $merged['meta']['raw'];
            $kept = array_filter( array( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) ) );
            foreach ( $kept as $item ) {
                echo $item['title'];
                echo $item['raw'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6', 'wp.xss.unescaped-output@10']);
});

it('keeps each value whole through array_values()', function (): void {
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show() {
            $rows = array( 'first' => array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            foreach ( array_values( $rows ) as $row ) {
                echo $row['title'];
                echo $row['raw'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});

it('keeps the parts of the element reset() and array_shift() return', function (): void {
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show() {
            $rows = array( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            $first = reset( $rows );
            echo $first['title'];
            echo $first['raw'];
            $next = array_shift( $rows );
            echo $next['title'];
            echo $next['raw'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@6', 'wp.xss.unescaped-output@9']);
});

it('traces an element reset() returns back to its source', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_show() {
            $rows = array( array( 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            $first = reset( $rows );
            echo $first['raw'];
        }
        PHP);

    $trace = $result->findings->all()[0]->trace;

    expect($trace[0]->description)->toContain("\$_GET['r']");
});

it('traces a value through array_values() and names the call', function (): void {
    $result = scanCode(<<<'PHP'
        <?php
        function acme_show() {
            $rows = array( 'first' => $_GET['r'], 'second' => 'Name' );
            foreach ( array_values( $rows ) as $row ) {
                echo $row;
            }
        }
        PHP);

    $steps = array_map(
        static fn (object $step): string => $step->description,
        $result->findings->all()[0]->trace,
    );

    expect($steps[0])->toContain("\$_GET['r']")
        ->and(implode("\n", $steps))->toContain('array_values() passes');
});

it('reads only the column array_column() names', function (): void {
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show() {
            $rows = array( array( 'id' => 7, 'title' => 'Hello', 'raw' => $_GET['r'] ) );
            foreach ( array_column( $rows, 'title' ) as $title ) {
                echo $title;
            }
            foreach ( array_column( $rows, 'raw', 'id' ) as $id => $raw ) {
                echo $id;
                echo $raw;
            }
            foreach ( array_column( $rows, 'title', 'raw' ) as $key => $title ) {
                echo $key;
            }
            $all = array_column( $rows, null, 'id' );
            echo $all[7]['title'];
            echo $all[7]['raw'];
        }
        PHP))->toBe([
            'wp.xss.unescaped-output@9',
            'wp.xss.unescaped-output@12',
            'wp.xss.unescaped-output@16',
        ]);
});

it('reads the filtered value out of the arguments apply_filters_ref_array() takes', function (): void {
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show() {
            $row = array( 'raw' => $_GET['r'], 'label' => 'Name' );
            $out = apply_filters_ref_array( 'acme_row', array( $row ) );
            echo $out['label'];
            echo $out['raw'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});

it('still reads a level away where a dispatcher hands the function items', function (): void {
    // array_map() hands array_values() each row, so each result is a list of
    // the row's values, which a read under an integer key finds. The
    // arguments call_user_func_array() spreads are not a literal here, so
    // array_filter() gets the row as its array. The pad value is one element
    // of array_pad()'s result, and not a list of them.
    expect(arrayFunctionFindings(<<<'PHP'
        function acme_show( $flag ) {
            $rows = array( array( 'raw' => $_GET['r'] ) );
            $lists = array_map( 'array_values', $rows );
            echo $lists[0][0];
            $args = array( array( 'raw' => array( 'x' => $_GET['r'] ) ) );
            if ( $flag ) {
                $args = array_reverse( $args );
            }
            $kept = call_user_func_array( 'array_filter', $args );
            echo $kept['raw']['x'];
            $padded = array_pad( array(), 2, array( 'raw' => array( 'x' => $_GET['r'] ) ) );
            echo $padded[0]['raw']['x'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@5', 'wp.xss.unescaped-output@11', 'wp.xss.unescaped-output@13']);
});
