<?php

declare(strict_types=1);

use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Scan\ScanProgress;
use Enshrined\WpTaint\Scan\WorkerPool;
use Enshrined\WpTaint\Taint\AnalysisOptions;

// Each fixed-point round is a phase of its own, counted in functions walked.
// A long round was a sentence that never moved: a whole-site scan sat at
// "round 1" for hours with no way to tell how far through it was.

/**
 * The fixed point's phases, in order, with the total each began with and the
 * steps it advanced.
 *
 * @return list<array{label: string, total: int|null, done: int}>
 */
function roundPhases(int $jobs): array
{
    $directory = dirname(__DIR__) . '/Fixtures/vulnerable';

    $progress = new class () implements ScanProgress {
        /** @var list<array{label: string, total: int|null, done: int}> */
        public array $phases = [];

        public function phase(string $label, ?int $total = null): void
        {
            $this->phases[] = ['label' => $label, 'total' => $total, 'done' => 0];
        }

        public function advance(int $steps = 1): void
        {
            $this->phases[array_key_last($this->phases)]['done'] += $steps;
        }

        public function note(string $message): void
        {
        }

        public function finish(): void
        {
        }
    };

    (new Scanner(testRegistry(), new AnalysisOptions(), $directory, jobs: $jobs, progress: $progress))
        ->scan((new FileFinder())->find([$directory]));

    return array_values(array_filter(
        $progress->phases,
        static fn (array $phase): bool => str_starts_with($phase['label'], 'Resolving taint across functions'),
    ));
}

it('counts every function of every round when the rounds run in this process', function (): void {
    $rounds = roundPhases(1);

    expect(count($rounds))->toBeGreaterThan(1);

    foreach ($rounds as $index => $round) {
        expect($round['label'])->toBe(sprintf('Resolving taint across functions, round %d', $index + 1));
        expect($round['total'])->toBeGreaterThan(0);
        expect($round['done'])->toBe($round['total']);
    }

    // The same functions every round: a skipped function is still walked.
    expect(array_unique(array_column($rounds, 'total')))->toHaveCount(1);
});

it('names each round but counts nothing when forked workers run them', function (): void {
    $rounds = roundPhases(2);

    expect(count($rounds))->toBeGreaterThan(1);

    foreach ($rounds as $index => $round) {
        expect($round['label'])->toBe(sprintf('Resolving taint across functions, round %d', $index + 1));
        expect($round['total'])->toBeNull();
        expect($round['done'])->toBe(0);
    }
})->skip(! WorkerPool::isSupported(), 'needs pcntl to fork workers');
