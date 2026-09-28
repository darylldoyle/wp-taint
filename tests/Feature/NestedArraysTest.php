<?php

declare(strict_types=1);

// An array nested in an array keeps its own elements apart, through a read, a
// loop, a copy and a join. `$a['x']['z']` no longer reads what `'y'` beside it
// was given.

/**
 * @return list<string> rule@line for each finding
 */
function nestedArrayFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps the elements of a nested literal apart', function (): void {
    expect(nestedArrayFindings(<<<'PHP'
        function acme_show() {
            $a = array( 'x' => array( 'y' => $_GET['v'], 'z' => 'safe' ) );
            echo $a['x']['z'];
            echo $a['x']['y'];
            $copy = $a;
            echo $copy['x']['z'];
            echo $copy['x']['y'];
        }
        PHP))->toBe(['wp.xss.unescaped-output@5', 'wp.xss.unescaped-output@8']);
});

it('keeps each row apart in a loop over rows', function (): void {
    expect(nestedArrayFindings(<<<'PHP'
        function acme_rows() {
            $rows = array( array( 'title' => $_GET['t'], 'id' => 7 ) );
            foreach ( $rows as $row ) {
                echo $row['id'];
                echo $row['title'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});

it('keeps an array\'s keys through a join', function (): void {
    expect(nestedArrayFindings(<<<'PHP'
        function acme_show( $wide ) {
            if ( $wide ) {
                $a = array( 'k' => $_GET['x'], 'j' => 'safe' );
            } else {
                $a = array( 'j' => 'also safe' );
            }
            echo $a['j'];
            echo $a['k'];
            $b = $wide ? array( 'title' => $_GET['t'], 'id' => 7 ) : array( 'id' => 8 );
            echo $b['id'];
            echo $b['title'];
            $rows = array();
            foreach ( array( 1, 2 ) as $n ) {
                $rows = array( 'row' => $n, 'label' => $_GET['l'] );
            }
            echo $rows['row'];
            echo $rows['label'];
        }
        PHP))->toBe([
            'wp.xss.unescaped-output@9',
            'wp.xss.unescaped-output@12',
            'wp.xss.unescaped-output@18',
        ]);
});

it('still reports a nested array read out whole', function (): void {
    // Flattened at the sink, the parts are all there.
    expect(nestedArrayFindings(<<<'PHP'
        function acme_show() {
            $a = array( 'x' => array( 'y' => $_GET['v'] ) );
            echo implode( ',', $a['x'] );
            echo implode( ',', $a );
        }
        PHP))->toBe(['wp.xss.unescaped-output@4', 'wp.xss.unescaped-output@5']);
});
