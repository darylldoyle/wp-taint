<?php

/**
 * Fetches the WordPress project's own intentionally vulnerable plugin.
 *
 * Everything else this project measures itself against, we wrote. The fixture
 * suite was authored alongside the engine and 37 of its cases were written
 * after the behaviour they test, which flatters us in a way no amount of care
 * removes. The corpus is third-party code but has no ground truth: nobody has
 * said which of its 1,046 findings are real.
 *
 * This has both. Jon Cave wrote it for the WordPress plugin review team in
 * 2013 to teach plugin authors what their own code does wrong, and the team
 * published a companion post enumerating every flaw and its fix. So it is a
 * scored test written by someone else, for a purpose that has nothing to do
 * with this tool, against an answer key we did not get to write.
 *
 *   https://make.wordpress.org/plugins/2013/04/09/intentionally-vulnerable-plugin/
 *   https://make.wordpress.org/plugins/2013/11/24/how-to-fix-the-intentionally-vulnerable-plugin/
 *
 * It is GPLv2+ and this project is MIT, so it is fetched rather than vendored.
 * The gist has not changed since April 2013; it is pinned to that commit so a
 * silent upstream edit cannot quietly move the score.
 *
 * Usage:
 *   php tools/fetch-vulnerable-plugin.php [--force]
 */

declare(strict_types=1);

const GIST = 'https://gist.github.com/5348689.git';
const PINNED = '80fcca0f1d7e6f8c86c4a1a0d6abb0855d74fb7a';

$root = dirname(__DIR__);
$target = $root . '/tests/Fixtures/vulnerable-plugin';
$force = in_array('--force', $argv, true);

if (is_dir($target) && ! $force) {
    printf("Already present at tests/Fixtures/vulnerable-plugin. Use --force to refetch.\n");

    exit(0);
}

if (is_dir($target)) {
    exec(sprintf('rm -rf %s', escapeshellarg($target)));
}

printf("Cloning the Damn Vulnerable WordPress Plugin...\n");

exec(sprintf('git clone --quiet %s %s 2>&1', escapeshellarg(GIST), escapeshellarg($target)), $output, $status);

if ($status !== 0) {
    fwrite(STDERR, sprintf("Clone failed:\n%s\n", implode("\n", $output)));

    exit(1);
}

exec(sprintf('git -C %s checkout --quiet %s 2>&1', escapeshellarg($target), PINNED), $output, $status);

if ($status !== 0) {
    fwrite(STDERR, sprintf("Could not check out the pinned revision %s.\n", PINNED));

    exit(1);
}

$head = trim((string) shell_exec(sprintf('git -C %s rev-parse HEAD', escapeshellarg($target))));

if ($head !== PINNED) {
    fwrite(STDERR, sprintf("Expected %s, got %s.\n", PINNED, $head));

    exit(1);
}

printf("Fetched at %s.\nRun: composer vulnerable:check\n", PINNED);
