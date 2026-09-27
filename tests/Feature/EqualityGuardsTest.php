<?php

declare(strict_types=1);

// A comparison with a literal is a guard, like an allowlist. `===` and `!==`
// hold the value to exactly that literal. A loose `==` and a `switch` case hold
// it only to a string that is not numeric, which a loose comparison cannot
// stretch. A check proves what it proves about the value it tested, and not
// about a value written after it under the same name.

/**
 * @return list<string> rule@line for each finding
 */
function equalityGuardFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('clears a value that passed a comparison with a literal', function (string $check): void {
    expect(equalityGuardFindings(<<<PHP
        function acme_view() {
            \$mode = \$_GET['mode'];
            if ( {$check} ) {
                echo \$mode;
            }
        }
        PHP))->toBe([]);
})->with([
    'a string' => ["'grid' === \$mode"],
    'a number' => ['$mode === 1'],
    'a constant' => ['$mode === ACME_MODE'],
    'a class constant' => ['$mode === Acme::GRID'],
    'loosely, a word' => ["\$mode == 'grid'"],
    'either of two' => ["'grid' === \$mode || 'list' === \$mode"],
    'empty' => ['empty( $mode )'],
]);

it('clears a value after a guard clause', function (string $check): void {
    expect(equalityGuardFindings(<<<PHP
        function acme_view() {
            \$mode = \$_GET['mode'];
            if ( {$check} ) {
                return;
            }
            echo \$mode;
        }
        PHP))->toBe([]);
})->with([
    'not the literal' => ["'grid' !== \$mode"],
    'neither of two' => ["'grid' !== \$mode && 'list' !== \$mode"],
    'loosely, not a word' => ["\$mode != 'grid'"],
    'not empty' => ['! empty( $mode )'],
]);

it('still reports a value the comparison does not hold', function (string $check): void {
    expect(equalityGuardFindings(<<<PHP
        function acme_view() {
            \$mode = \$_GET['mode'];
            if ( {$check} ) {
                echo \$mode;
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@5']);
})->with([
    'not the literal' => ["'grid' !== \$mode"],
    'loosely, true' => ['$mode == true'],
    'loosely, a number' => ['$mode == 1'],
    'loosely, a numeric string' => ["\$mode == '1'"],
    'one side unchecked' => ["'grid' === \$mode || acme_ok()"],
    'another variable' => ["'grid' === \$other"],
    'not empty' => ['! empty( $mode )'],
]);

it('clears a value inside a switch case on a word, and only there', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view() {
            $view = $_GET['view'];
            switch ( $view ) {
                case 'grid':
                case 'list':
                    echo $view;
                    break;
                case '1':
                    echo $view;
                    break;
                case true:
                    echo $view;
                    break;
                default:
                    echo $view;
            }
        }
        PHP))->toBe([
        'wp.xss.unescaped-output@10',
        'wp.xss.unescaped-output@13',
        'wp.xss.unescaped-output@16',
    ]);
});

it('clears an option name a switch case settles', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_save() {
            foreach ( $_POST as $option => $value ) {
                switch ( $option ) {
                    case 'acme_title':
                    case 'acme_tagline':
                        update_option( $option, sanitize_text_field( $value ) );
                        break;
                }
            }
        }
        PHP))->toBe([]);
});

it('clears a match arm on literals', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view() {
            $mode = $_GET['mode'];
            echo match ( $mode ) {
                'grid', 'list' => $mode,
                default => 'grid',
            };
        }
        PHP))->toBe([]);
});

it('does not credit a check for a value written after it', function (string $write): void {
    expect(equalityGuardFindings(<<<PHP
        function acme_view() {
            \$title = \$_GET['title'];
            if ( empty( \$title ) ) {
                \$title = {$write};
                echo \$title;
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
})->with([
    'another request value' => ["\$_POST['fallback']"],
    'one built from the checked value' => ["\$title . \$_POST['suffix']"],
]);

it('does not credit a digit check for a value written after it', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view() {
            $id = $_GET['id'];
            if ( ! ctype_digit( $id ) ) {
                return;
            }
            $id = $id . $_GET['suffix'];
            echo $id;
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});

it('does not credit a check for a value a loop writes after it', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view() {
            $x = $_GET['x'];
            if ( 'a' === $x ) {
                do {
                    echo $x;
                    $x = $_GET['y'];
                } while ( acme_more() );
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@6']);
});

it('keeps a check through a join with a value computed from the checked one', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view( $pad ) {
            $id = $_GET['id'];
            if ( ! ctype_digit( $id ) ) {
                return;
            }
            if ( $pad ) {
                $id = str_pad( $id, 8, '0' );
            }
            echo $id;
        }
        PHP))->toBe([]);
});

it('does not keep a check through a join with a value written after it', function (): void {
    expect(equalityGuardFindings(<<<'PHP'
        function acme_view( $other ) {
            $id = $_GET['id'];
            if ( ! ctype_digit( $id ) ) {
                return;
            }
            if ( $other ) {
                $id = $_GET['other'];
            }
            echo $id;
        }
        PHP))->toBe(['wp.xss.unescaped-output@10']);
});
