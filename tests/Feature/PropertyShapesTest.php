<?php

declare(strict_types=1);

// A property holds its value as a shape: an array written into it whole keeps
// its elements under their keys, and a read of one element sees only what that
// element was given.

/**
 * @return list<string> rule@line for each finding
 */
function propertyShapeFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('keeps the elements of an array written into a property apart', function (): void {
    // The literal's elements never reached the property, so lines 9 and 12
    // were missed. Had they reached it as one set, lines 8 and 11 would have
    // been reported too.
    expect(propertyShapeFindings(<<<'PHP'
        class Acme_Box {
            private $opts = array();
            public function load() {
                $this->opts = array( 'name' => $_GET['n'], 'mode' => 'grid' );
            }
            public function show() {
                echo $this->opts['mode'];
                echo $this->opts['name'];
                $copy = $this->opts;
                echo $copy['mode'];
                echo $copy['name'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@9', 'wp.xss.unescaped-output@12']);
});

it('keeps apart the elements a constructor builds from its parameter', function (): void {
    expect(propertyShapeFindings(<<<'PHP'
        class Acme_Card {
            private $data;
            public function __construct( $title ) {
                $this->data = array( 'title' => $title, 'id' => 7 );
            }
            public function render() {
                echo $this->data['id'];
                echo $this->data['title'];
            }
        }
        function acme_card() {
            $card = new Acme_Card( $_GET['t'] );
            $card->render();
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('keeps the elements of a static property apart', function (): void {
    expect(propertyShapeFindings(<<<'PHP'
        class Acme_Cache {
            private static $entry = array();
            public static function fill() {
                self::$entry = array( 'path' => $_GET['p'], 'size' => 1 );
            }
            public static function show() {
                echo self::$entry['size'];
                echo self::$entry['path'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('keeps a nested array apart in a property', function (): void {
    expect(propertyShapeFindings(<<<'PHP'
        class Acme_Report {
            private $rows;
            public function load() {
                $this->rows = array( 'head' => array( 'label' => 'Name', 'raw' => $_GET['r'] ) );
            }
            public function show() {
                echo $this->rows['head']['label'];
                echo $this->rows['head']['raw'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@9']);
});

it('still reports what a property holds as a whole', function (): void {
    // A value written whole taints every element read from it.
    expect(propertyShapeFindings(<<<'PHP'
        class Acme_Raw {
            private $all;
            public function load() {
                $this->all = $_GET;
            }
            public function show() {
                echo $this->all['anything'];
            }
        }
        PHP))->toBe(['wp.xss.unescaped-output@8']);
});
