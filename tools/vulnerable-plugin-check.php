<?php

/**
 * Scores this engine against somebody else's answer key.
 *
 * The fixture suite is ours and flatters us. The corpus is third-party code
 * with no ground truth. This is the one benchmark that is both: a plugin the
 * WordPress plugin review team wrote in 2013 to teach authors what their code
 * does wrong, and a companion post enumerating every flaw in it.
 *
 * Every issue in the answer key is either caught or recorded as missed. There
 * is no out-of-scope category, on purpose: three of the issues are CSRF and
 * control-flow bugs the taint engine cannot see, and this project runs
 * structural rules beside the dataflow precisely so that "the taint engine
 * cannot see it" stops being an excuse.
 *
 * The check fails in both directions. A `caught` issue that stops being
 * reported is a regression. A `missed` issue that starts being reported means
 * someone fixed something without noticing, and leaving the file stale would
 * misrepresent where the tool stands.
 *
 * Usage:
 *   php tools/vulnerable-plugin-check.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Enshrined\WpTaint\Registry\RegistryLoader;
use Enshrined\WpTaint\Scan\FileFinder;
use Enshrined\WpTaint\Scan\Scanner;
use Enshrined\WpTaint\Taint\AnalysisOptions;

const TRUTH = __DIR__ . '/../tests/Fixtures/vulnerable-plugin-truth.json';
const PLUGIN = __DIR__ . '/../tests/Fixtures/vulnerable-plugin';

if (! is_dir(PLUGIN)) {
    fwrite(STDERR, "The plugin is not present.\nRun: composer vulnerable:fetch\n");

    exit(1);
}

$body = file_get_contents(TRUTH);

if ($body === false) {
    fwrite(STDERR, "Cannot read the ground truth file.\n");

    exit(1);
}

/** @var array{issues: list<array{id: int, class: string, title: string, file: string, lines: list<int>, status: string, expectedRule?: string, note?: string}>} $truth */
$truth = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

$registry = (new RegistryLoader(__DIR__ . '/../registries'))->load('wordpress')->configured(true, false);
$result = (new Scanner($registry, new AnalysisOptions(), PLUGIN, jobs: 1))
    ->scan((new FileFinder())->find([PLUGIN]));

/** @var array<string, list<string>> $reported line key => rule ids */
$reported = [];

foreach ($result->findings->all() as $finding) {
    $key = basename($finding->file) . ':' . $finding->line;
    $reported[$key] = [...($reported[$key] ?? []), $finding->ruleId];
}

$failures = [];
$caught = 0;
$missed = 0;

foreach ($truth['issues'] as $issue) {
    if ($issue['status'] === 'modelled') {
        continue;
    }

    $hits = [];

    foreach ($issue['lines'] as $line) {
        $key = $issue['file'] . ':' . $line;

        if (isset($reported[$key])) {
            $hits[] = $key;
        }
    }

    $isCaught = $hits !== [];
    $expected = $issue['status'] === 'caught';

    if ($isCaught) {
        $caught++;
    } else {
        $missed++;
    }

    if ($isCaught === $expected) {
        printf(
            "  %s #%-2d %-8s %s\n",
            $isCaught ? '✓' : '·',
            $issue['id'],
            $issue['class'],
            $issue['title'],
        );

        continue;
    }

    $failures[] = $expected
        ? sprintf(
            "  #%d (%s) is recorded as caught and was not reported.\n      %s\n      A regression: something stopped seeing it.",
            $issue['id'],
            $issue['class'],
            $issue['title'],
        )
        : sprintf(
            "  #%d (%s) is recorded as missed and WAS reported at %s.\n      %s\n      Good news. Update its status to \"caught\" in the truth file.",
            $issue['id'],
            $issue['class'],
            implode(', ', $hits),
            $issue['title'],
        );

    printf(
        "  %s #%-2d %-8s %s\n",
        $isCaught ? '!' : 'X',
        $issue['id'],
        $issue['class'],
        $issue['title'],
    );
}

$scored = $caught + $missed;

printf(
    "\n  %d of %d documented issues caught · %d findings reported · %d files\n",
    $caught,
    $scored,
    count($result->findings->all()),
    $result->filesScanned,
);

if ($failures !== []) {
    fwrite(STDERR, "\nThe score no longer matches the recorded one:\n\n" . implode("\n\n", $failures) . "\n");

    exit(1);
}

printf("  Matches the recorded score.\n");

exit(0);
