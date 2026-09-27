<?php

declare(strict_types=1);

// A few of PHP's classes hold text: what goes into a DOMDocument comes back out
// of saveHTML(). Their methods returned clean, so a document loaded from the
// request and echoed was missed. Every other class of PHP's still holds
// nothing of its own.

/**
 * @return list<string> rule@line for each finding
 */
function textClassFindings(string $body): array
{
    return findingSignatures(scanCode("<?php\n" . $body));
}

it('returns what a document was given', function (): void {
    expect(textClassFindings(<<<'PHP'
        function acme_loaded() {
            $dom = new DOMDocument();
            $dom->loadHTML( $_POST['html'] );
            echo $dom->saveHTML();
        }
        function acme_built() {
            $dom = new DOMDocument();
            $p = $dom->createElement( 'p', $_GET['text'] );
            $dom->appendChild( $p );
            echo $dom->saveHTML();
        }
        function acme_fixed() {
            $dom = new DOMDocument();
            $dom->loadHTML( '<p>Fixed</p>' );
            echo $dom->saveHTML();
        }
        PHP))->toBe(['wp.xss.unescaped-output@5', 'wp.xss.unescaped-output@11']);
});

it('returns what a container was given', function (): void {
    expect(textClassFindings(<<<'PHP'
        function acme_object() {
            $o = new ArrayObject( $_POST );
            echo $o->getArrayCopy()['x'];
        }
        function acme_queue() {
            $q = new SplQueue();
            $q->enqueue( $_GET['job'] );
            echo $q->dequeue();
        }
        PHP))->toBe(['wp.xss.unescaped-output@4', 'wp.xss.unescaped-output@9']);
});

it('reads a parsed document through its properties', function (): void {
    expect(textClassFindings(<<<'PHP'
        function acme_run() {
            $xml = simplexml_load_string( $_POST['xml'] );
            echo $xml->title;
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('returns an exception\'s message', function (): void {
    expect(textClassFindings(<<<'PHP'
        function acme_run() {
            $e = new InvalidArgumentException( 'Bad value: ' . $_GET['v'] );
            echo $e->getMessage();
        }
        PHP))->toBe(['wp.xss.unescaped-output@4']);
});

it('keeps a class that holds no text clean', function (): void {
    expect(textClassFindings(<<<'PHP'
        function acme_run() {
            $when = new DateTime( $_GET['when'] );
            echo $when->format( 'Y-m-d' );
        }
        PHP))->toBe([]);
});
