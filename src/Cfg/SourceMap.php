<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Turns byte offsets into 1-based line and column numbers, and hands back
 * source lines for trace rendering.
 *
 * php-cfg gives us `startFilePos` but no column, so this is where columns come
 * from. Offsets are byte offsets, and columns are counted in bytes for the same
 * reason SARIF and most editors do.
 */
final class SourceMap
{
    /** @var list<int> byte offset at which each 1-based line starts */
    private array $lineOffsets;

    /** @var list<string> */
    private array $lines;

    public function __construct(private readonly string $source)
    {
        $this->lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $source));

        $offsets = [0];
        $offset = 0;
        $length = strlen($source);

        for ($i = 0; $i < $length; $i++) {
            if ($source[$i] === "\n") {
                $offsets[] = $i + 1;
            }
        }

        unset($offset);

        $this->lineOffsets = $offsets;
    }

    public static function fromFile(string $path): self
    {
        $source = is_readable($path) ? file_get_contents($path) : false;

        return new self($source === false ? '' : $source);
    }

    /**
     * @return array{line: int, column: int} 1-based
     */
    public function positionAt(int $offset): array
    {
        if ($offset < 0) {
            return ['line' => 0, 'column' => 0];
        }

        $low = 0;
        $high = count($this->lineOffsets) - 1;

        while ($low < $high) {
            $mid = intdiv($low + $high + 1, 2);

            if (($this->lineOffsets[$mid] ?? PHP_INT_MAX) <= $offset) {
                $low = $mid;
            } else {
                $high = $mid - 1;
            }
        }

        return [
            'line' => $low + 1,
            'column' => $offset - ($this->lineOffsets[$low] ?? 0) + 1,
        ];
    }

    /**
     * The 1-based source line, without its trailing newline.
     */
    public function line(int $line): string
    {
        return $this->lines[$line - 1] ?? '';
    }

    public function lineCount(): int
    {
        return count($this->lines);
    }

    public function source(): string
    {
        return $this->source;
    }
}
