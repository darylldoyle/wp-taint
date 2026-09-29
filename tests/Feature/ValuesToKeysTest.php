<?php

declare(strict_types=1);

// array_flip(), array_combine() and array_fill_keys() make the first array's
// values the result's keys, so request data used as a key reaches a foreach
// key and array_keys(). array_flip() also makes the keys the values.

/**
 * @return list<int> the lines reported, for a function body
 */
function valuesToKeysLines(string $body): array
{
    $lines = array_map(
        static fn (object $finding): int => $finding->line,
        scanCode("<?php\nfunction acme_show() {\n" . $body . "\n}\n")->findings->all(),
    );
    sort($lines);

    return $lines;
}

it('carries the values into the keys', function (string $body): void {
    expect(valuesToKeysLines($body))->toBe([4]);
})->with([
    'array_flip() read by foreach' => [<<<'PHP'
        $ids = array_flip( array( $_GET['x'] ) );
        foreach ( $ids as $id => $on ) { echo $id; }
        PHP],
    'array_flip() read by array_keys()' => [<<<'PHP'
        $ids = array_flip( array( $_GET['x'] ) );
        echo implode( ',', array_keys( $ids ) );
        PHP],
    'array_combine() read by array_keys()' => [<<<'PHP'
        $map = array_combine( array( $_GET['k'] ), array( 'v' ) );
        echo implode( ',', array_keys( $map ) );
        PHP],
    'array_fill_keys() read by foreach' => [<<<'PHP'
        $ids = array_fill_keys( array( $_GET['k'] ), true );
        foreach ( $ids as $id => $on ) { echo $id; }
        PHP],
]);

it('keeps each value where the function puts it', function (): void {
    expect(valuesToKeysLines(<<<'PHP'
        $flipped = array_flip( array( 'a' => $_GET['v'] ) );
        echo implode( ',', $flipped );
        $map = array_combine( array( 'a' ), array( $_GET['v'] ) );
        echo $map['a'];
        $filled = array_fill_keys( array( 'a', 'b' ), $_GET['v'] );
        echo $filled['b'];
        $keys = array_fill_keys( array( $_GET['k'] ), 'on' );
        echo implode( ',', $keys );
        PHP))->toBe([6, 8]);
});
