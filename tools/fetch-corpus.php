<?php

/**
 * Downloads the most-installed plugins from the WordPress.org repository into
 * `tests/Fixtures/corpus/`, which is gitignored.
 *
 * The corpus is the parse-rate gate, the performance benchmark and the false
 * positive triage set. It is not committed: it is ~50 third-party plugins under
 * assorted licences, and it changes every time upstream releases.
 *
 * Usage:
 *   php tools/fetch-corpus.php [--count=50] [--force]
 *   php tools/fetch-corpus.php --lock [--force]
 *
 * `--lock` fetches the pinned subset in `tests/Fixtures/corpus-lock.json`
 * instead of the popular list. Pinned because the tracked finding count in CI
 * has to move only when *this* project changes: a baseline that drifts whenever
 * a plugin releases teaches people to ignore it.
 *
 * This is the only part of the project that touches the network, and it is a
 * developer tool, never on the analysis path.
 */

declare(strict_types=1);

const API_ENDPOINT = 'https://api.wordpress.org/plugins/info/1.2/';

$options = getopt('', ['count::', 'force', 'lock']);
$count = isset($options['count']) ? max(1, (int) $options['count']) : 50;
$force = isset($options['force']);
$locked = isset($options['lock']);

$root = dirname(__DIR__);
$corpus = $root . '/tests/Fixtures/corpus';
$cache = $root . '/tools/corpus-cache';

foreach ([$corpus, $cache] as $directory) {
    if (! is_dir($directory) && ! mkdir($directory, 0o755, true) && ! is_dir($directory)) {
        fwrite(STDERR, sprintf("Unable to create %s\n", $directory));

        exit(1);
    }
}

$versions = [];

if ($locked) {
    $versions = readLock($root . '/tests/Fixtures/corpus-lock.json');
    $slugs = array_keys($versions);
    printf("Fetching %d pinned plugins.\n", count($slugs));
} else {
    echo "Querying the WordPress.org plugin API...\n";

    $slugs = fetchPopularSlugs($count);
}

if ($slugs === []) {
    fwrite(STDERR, "No plugins to fetch. Check network access and try again.\n");

    exit(1);
}

printf("Found %d plugins. Downloading into %s\n\n", count($slugs), $corpus);

$installed = 0;
$skipped = 0;
$failed = [];

foreach ($slugs as $index => $slug) {
    $target = $corpus . '/' . $slug;

    if (is_dir($target) && ! $force) {
        printf("  [%2d/%2d] %-40s already present\n", $index + 1, count($slugs), $slug);
        $skipped++;

        continue;
    }

    printf("  [%2d/%2d] %-40s ", $index + 1, count($slugs), $slug);

    try {
        $zip = downloadZip($slug, $cache, $versions[$slug] ?? null);
        extractZip($zip, $corpus, $target, $force);
        printf("ok\n");
        $installed++;
    } catch (RuntimeException $error) {
        printf("FAILED — %s\n", $error->getMessage());
        $failed[] = $slug;
    }
}

printf("\n%d installed, %d already present, %d failed.\n", $installed, $skipped, count($failed));

if ($failed !== []) {
    printf("Failed: %s\n", implode(', ', $failed));
}

printf("\nNext: vendor/bin/wp-taint scan %s --parse-report\n", 'tests/Fixtures/corpus');

/**
 * @return list<string>
 */
function fetchPopularSlugs(int $count): array
{
    $slugs = [];
    $page = 1;
    $perPage = 100;

    while (count($slugs) < $count && $page <= 5) {
        $query = http_build_query([
            'action' => 'query_plugins',
            'request[browse]' => 'popular',
            'request[page]' => $page,
            'request[per_page]' => $perPage,
            'request[fields][short_description]' => 0,
            'request[fields][description]' => 0,
            'request[fields][sections]' => 0,
            'request[fields][screenshots]' => 0,
            'request[fields][ratings]' => 0,
            'request[fields][icons]' => 0,
            'request[fields][banners]' => 0,
        ]);

        $body = httpGet(API_ENDPOINT . '?' . $query);
        $data = json_decode($body, true);

        if (! is_array($data) || ! isset($data['plugins']) || ! is_array($data['plugins'])) {
            break;
        }

        foreach ($data['plugins'] as $plugin) {
            if (! is_array($plugin) || ! isset($plugin['slug']) || ! is_string($plugin['slug'])) {
                continue;
            }

            $slugs[$plugin['slug']] = true;

            if (count($slugs) >= $count) {
                break;
            }
        }

        if ($data['plugins'] === []) {
            break;
        }

        $page++;
    }

    $result = array_keys($slugs);
    sort($result);

    return array_slice($result, 0, $count);
}

/**
 * @return array<string, string> slug => exact version
 */
function readLock(string $path): array
{
    $body = file_get_contents($path);

    if ($body === false) {
        throw new RuntimeException(sprintf('Cannot read %s.', $path));
    }

    /** @var array{plugins?: array<string, string>} $data */
    $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    $plugins = $data['plugins'] ?? [];

    ksort($plugins);

    return $plugins;
}

function downloadZip(string $slug, string $cache, ?string $version = null): string
{
    $path = $cache . '/' . $slug . ($version === null ? '' : '-' . $version) . '.zip';

    if (is_file($path) && filesize($path) > 0) {
        return $path;
    }

    // An exact version when one is pinned, so the tracked count in CI moves
    // only when this project changes.
    $body = httpGet($version === null
        ? sprintf('https://downloads.wordpress.org/plugin/%s.latest-stable.zip', $slug)
        : sprintf('https://downloads.wordpress.org/plugin/%s.%s.zip', $slug, $version));

    if (strlen($body) < 100) {
        throw new RuntimeException('download was empty');
    }

    file_put_contents($path, $body);

    return $path;
}

function extractZip(string $zipPath, string $corpus, string $target, bool $force): void
{
    if ($force && is_dir($target)) {
        removeDirectory($target);
    }

    $zip = new ZipArchive();

    if ($zip->open($zipPath) !== true) {
        throw new RuntimeException('archive could not be opened');
    }

    // Extract PHP files only. The corpus is a parse and analysis benchmark;
    // images, CSS and translation binaries are dead weight on disk.
    $entries = [];

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = $zip->getNameIndex($i);

        if ($name === false || str_ends_with($name, '/')) {
            continue;
        }

        if (strtolower(pathinfo($name, PATHINFO_EXTENSION)) !== 'php') {
            continue;
        }

        if (str_contains($name, '..')) {
            continue;
        }

        $entries[] = $name;
    }

    if ($entries === []) {
        $zip->close();

        throw new RuntimeException('archive contained no PHP files');
    }

    $zip->extractTo($corpus, $entries);
    $zip->close();
}

function removeDirectory(string $directory): void
{
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $item) {
        if ($item instanceof SplFileInfo) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }
    }

    rmdir($directory);
}

function httpGet(string $url): string
{
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 60,
            'header' => "User-Agent: wp-taint corpus fetcher (https://github.com/darylldoyle/wp-taint)\r\n",
            'follow_location' => 1,
            'max_redirects' => 5,
        ],
    ]);

    $body = @file_get_contents($url, false, $context);

    if ($body === false) {
        throw new RuntimeException(sprintf('request failed: %s', $url));
    }

    return $body;
}
