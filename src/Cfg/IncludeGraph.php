<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Which file each `include` site loads, resolved once before analysis.
 *
 * Keyed by the *op* rather than by file, because one file routinely includes
 * several others and the analysis needs to know which site joined which scope
 * when it builds the trace.
 */
final class IncludeGraph
{
    /** @var array<string, list<string>> "file:line:column" => relative paths included there */
    private array $targets = [];

    /** @var list<array{file: string, line: int, reason: string}> */
    private array $unresolved = [];

    /**
     * @param list<string> $files
     */
    public function record(string $site, array $files): void
    {
        $this->targets[$site] = $files;
    }

    public function recordUnresolved(string $file, int $line, string $reason): void
    {
        $this->unresolved[] = ['file' => $file, 'line' => $line, 'reason' => $reason];
    }

    /**
     * @return list<string>
     */
    public function targetsFor(string $site): array
    {
        return $this->targets[$site] ?? [];
    }

    /**
     * @return list<array{file: string, line: int, reason: string}>
     */
    public function unresolved(): array
    {
        $unresolved = $this->unresolved;

        usort(
            $unresolved,
            static fn (array $a, array $b): int => [$a['file'], $a['line']] <=> [$b['file'], $b['line']],
        );

        return $unresolved;
    }

    public function resolvedCount(): int
    {
        return count($this->targets);
    }

    public function unresolvedCount(): int
    {
        return count($this->unresolved);
    }

    public static function siteKey(string $file, int $line, int $offset): string
    {
        return $file . ':' . $line . ':' . $offset;
    }
}
