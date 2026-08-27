<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cfg\SourceMap;

it('converts byte offsets to 1-based line and column', function (): void {
    $map = new SourceMap("<?php\n\$a = 1;\n\$b = 2;\n");

    expect($map->positionAt(0))->toBe(['line' => 1, 'column' => 1]);
    expect($map->positionAt(6))->toBe(['line' => 2, 'column' => 1]);
    expect($map->positionAt(9))->toBe(['line' => 2, 'column' => 4]);
    expect($map->positionAt(14))->toBe(['line' => 3, 'column' => 1]);
});

it('returns source lines without their newline', function (): void {
    $map = new SourceMap("<?php\necho 'hi';\n");

    expect($map->line(1))->toBe('<?php');
    expect($map->line(2))->toBe("echo 'hi';");
    expect($map->line(99))->toBe('');
});

it('normalises Windows and classic Mac line endings', function (): void {
    $map = new SourceMap("<?php\r\necho 1;\r\n");

    expect($map->line(2))->toBe('echo 1;');
});

it('handles a negative offset without blowing up', function (): void {
    expect((new SourceMap('<?php'))->positionAt(-1))->toBe(['line' => 0, 'column' => 0]);
});

it('handles an empty file', function (): void {
    $map = new SourceMap('');

    expect($map->lineCount())->toBe(1);
    expect($map->positionAt(0))->toBe(['line' => 1, 'column' => 1]);
});
