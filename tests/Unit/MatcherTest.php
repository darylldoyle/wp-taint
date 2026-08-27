<?php

declare(strict_types=1);

use Enshrined\WpTaint\Registry\Matcher;

it('normalises function names case-insensitively and without a leading separator', function (): void {
    expect(Matcher::function('ESC_HTML')->key())->toBe(Matcher::function('\esc_html')->key());
});

it('keys each matcher kind distinctly', function (): void {
    $keys = [
        Matcher::superglobal('_GET')->key(),
        Matcher::function('esc_html')->key(),
        Matcher::method('wpdb', 'query')->key(),
        Matcher::staticMethod('wpdb', 'query')->key(),
        Matcher::construct('echo')->key(),
    ];

    expect(count(array_unique($keys)))->toBe(5);
});

it('strips the sigil from superglobal names', function (): void {
    expect(Matcher::superglobal('$_GET')->key())->toBe(Matcher::superglobal('_GET')->key());
    expect(Matcher::superglobal('_GET')->describe())->toBe('$_GET');
});

it('rejects unknown constructs', function (): void {
    expect(static fn (): Matcher => Matcher::construct('goto'))
        ->toThrow(InvalidArgumentException::class, 'Unknown construct "goto"');
});

it('does not offer a backtick construct, because php-cfg lowers backticks to shell_exec', function (): void {
    expect(Matcher::supportedConstructs())->not->toContain('backtick');
});

it('describes and identifies entries readably', function (): void {
    expect(Matcher::function('esc_html')->describe())->toBe('esc_html()');
    expect(Matcher::method('wpdb', 'query')->describe())->toBe('wpdb::query()');
    expect(Matcher::method('wpdb', 'query')->identity())->toBe('wpdb::query');
    expect(Matcher::construct('echo')->identity())->toBe('echo');
});
