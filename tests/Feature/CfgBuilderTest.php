<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\CfgBuilder;

function build(string $code): Enshrined\WpTaint\Cfg\ParseResult
{
    return (new CfgBuilder('/tmp'))->build($code, '/tmp/snippet.php');
}

it('returns a structured error rather than null on a syntax error', function (): void {
    $result = build('<?php function ( { ');

    expect($result->isSuccess())->toBeFalse();
    expect($result->error()->line)->toBeGreaterThan(0);
    expect($result->error()->message)->not->toBeEmpty();
});

it('refuses to hand back a file it could not parse', function (): void {
    $result = build('<?php $ = 1;');

    expect(static fn (): object => $result->file())->toThrow(LogicException::class);
});

it('refuses to hand back an error for a file it did parse', function (): void {
    $result = build('<?php echo 1;');

    expect(static fn (): object => $result->error())->toThrow(LogicException::class);
});

it('reports a missing file as a parse error rather than throwing', function (): void {
    $result = (new CfgBuilder('/tmp'))->buildFromFile('/tmp/definitely-not-here-' . bin2hex(random_bytes(4)) . '.php');

    expect($result->isSuccess())->toBeFalse();
    expect($result->error()->message)->toContain('Unable to read file');
});

it('keeps the AST alongside the CFG', function (): void {
    // Structural rules ask shape questions, which the AST states directly and
    // the CFG has already dissolved.
    $parsed = build('<?php register_rest_route("a/v1", "/b", []);')->file();

    expect($parsed->ast())->not->toBeEmpty();
    expect($parsed->script->main)->not->toBeNull();
});

describe('lowering constructs php-cfg cannot parse', function (): void {
    it('lowers match to a ternary chain', function (): void {
        $result = build('<?php $x = match (1) { 1 => "a", default => "b" };');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('match');
    });

    it('lowers nullsafe access', function (): void {
        $result = build('<?php $o = null; echo $o?->p; echo $o?->m();');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('nullsafe-property-fetch');
        expect($result->file()->lowered)->toHaveKey('nullsafe-method-call');
    });

    it('lowers enums to a final class with constant cases', function (): void {
        $result = build('<?php enum S: string { case A = "a"; public function l(): string { return $this->value; } }');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('enum');
        expect($result->file()->lowered)->toHaveKey('enum-case');

        // The method body has to survive, or the rewrite would be a silent
        // false negative for anything inside an enum.
        expect($result->file()->script->functions)->not->toBeEmpty();
    });

    it('lowers first-class callables to their pre-8.1 equivalents', function (): void {
        $result = build('<?php $f = strlen(...); $g = Foo::bar(...); $o = new stdClass(); $h = $o->m(...);');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered['first-class-callable'])->toBe(3);
    });

    it('lowers intersection and DNF types', function (): void {
        $result = build('<?php interface I{} interface J{} function h(I&J $x): I&J { return $x; }');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('intersection-type');
    });

    it('lowers yield from', function (): void {
        $result = build('<?php function g() { yield from [1, 2]; }');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('yield-from');
    });

    it('writes an explicit null default onto an uninitialised static variable', function (): void {
        // Not a language gap but a php-cfg bug: the typed property is left
        // uninitialised and its own Simplifier throws reading it. This
        // accounted for 33 of 36 corpus parse failures.
        $result = build('<?php function a() { static $c; $c++; return $c; }');

        expect($result->isSuccess())->toBeTrue();
        expect($result->file()->lowered)->toHaveKey('static-var-without-default');
    });

    it('leaves ordinary code alone', function (): void {
        $result = build('<?php echo esc_html($_GET["q"]);');

        expect($result->file()->lowered)->toBe([]);
    });

    it('keeps source positions accurate through a rewrite', function (): void {
        $result = scanCode(<<<'PHP'
            <?php
            $mode = $_GET['mode'];
            $label = match ($mode) {
                'a' => $mode,
                default => 'x',
            };
            echo $label;
            PHP);

        expect($result->findings)->toHaveCount(1);
        expect($result->findings->all()[0]->line)->toBe(7);
    });
});
