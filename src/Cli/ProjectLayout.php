<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cli;

/**
 * The first-party directories a WordPress tree offers to scan.
 *
 * `wp-taint init` needs to turn "point me at wp-content" into a list of themes
 * and plugins a developer might have written, so it can ask which are theirs
 * and write the config. The listing is the testable half; the asking is the
 * command's.
 *
 * A directory is a candidate when it is a theme, a plugin, or an mu-plugin —
 * the three places first-party code lives — found by the layout WordPress
 * mandates rather than by reading any file. Vendor and build directories are
 * never candidates: nobody scans `node_modules` on purpose.
 */
final class ProjectLayout
{
    private const SKIP = ['vendor', 'node_modules', 'dist', 'build', '.git'];

    /**
     * @param list<string> $themes    relative paths, e.g. "themes/acme"
     * @param list<string> $plugins   relative paths, e.g. "plugins/acme"
     * @param list<string> $muPlugins relative paths, e.g. "client-mu-plugins/acme"
     */
    private function __construct(
        public readonly array $themes,
        public readonly array $plugins,
        public readonly array $muPlugins,
    ) {
    }

    /**
     * Read the candidate directories under a wp-content-shaped root.
     *
     * The root may be the wp-content directory itself, or a parent of it — a
     * project checkout that holds `wp-content/` somewhere inside. The first
     * `wp-content` found is used.
     */
    public static function discover(string $root): self
    {
        $content = self::locateContent($root);

        if ($content === null) {
            return new self([], [], []);
        }

        return new self(
            self::childrenOf($content . '/themes', 'themes'),
            self::childrenOf($content . '/plugins', 'plugins'),
            [
                ...self::childrenOf($content . '/mu-plugins', 'mu-plugins'),
                ...self::childrenOf($content . '/client-mu-plugins', 'client-mu-plugins'),
            ],
        );
    }

    /**
     * Every candidate, themes then plugins then mu-plugins.
     *
     * @return list<string>
     */
    public function all(): array
    {
        return [...$this->themes, ...$this->plugins, ...$this->muPlugins];
    }

    public function isEmpty(): bool
    {
        return $this->all() === [];
    }

    private static function locateContent(string $root): ?string
    {
        $root = rtrim(str_replace('\\', '/', $root), '/');

        if (is_dir($root . '/themes') || is_dir($root . '/plugins')) {
            return $root;
        }

        if (is_dir($root . '/wp-content')) {
            return $root . '/wp-content';
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private static function childrenOf(string $directory, string $prefix): array
    {
        if (! is_dir($directory)) {
            return [];
        }

        $entries = scandir($directory);

        if ($entries === false) {
            return [];
        }

        $found = [];

        foreach ($entries as $entry) {
            if ($entry[0] === '.' || in_array($entry, self::SKIP, true)) {
                continue;
            }

            if (is_dir($directory . '/' . $entry)) {
                $found[] = $prefix . '/' . $entry;
            }
        }

        sort($found);

        return $found;
    }
}
