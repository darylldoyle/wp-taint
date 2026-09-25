<?php

declare(strict_types=1);

use Enshrined\WpTaint\Cli\MemoryScanProgress;
use Symfony\Component\Console\Output\BufferedOutput;

it('reports each phase when the next one starts, and each round of the fixed point', function (): void {
    $output = new BufferedOutput();
    $progress = new MemoryScanProgress($output);

    $progress->phase('Parsing', 2);
    $progress->advance();
    $progress->advance();
    $progress->phase('Resolving taint across functions', null);
    $progress->advance();
    $progress->advance();
    $progress->advance();
    $progress->finish();

    $lines = array_values(array_filter(explode("\n", $output->fetch())));

    expect($lines)->toHaveCount(5);
    expect($lines[0])->toStartWith('[memory] Parsing ');
    expect($lines[1])->toStartWith('[memory] Resolving taint across functions, round 1 ');
    expect($lines[2])->toStartWith('[memory] Resolving taint across functions, round 2 ');
    expect($lines[3])->toStartWith('[memory] Resolving taint across functions, round 3 ');
    expect($lines[4])->toStartWith('[memory] total ');

    foreach (array_slice($lines, 0, 4) as $line) {
        expect($line)->toMatch('/heap +[\d,]+MB  peak +[\d,]+MB$/');
    }
});
