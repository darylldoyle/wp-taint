<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Which theme, if any, a scanned file belongs to.
 *
 * `get_template_directory()` is a runtime question — "where is the active
 * theme" — with a static answer whenever the calling file is itself inside a
 * theme in the scan: the theme a file belongs to is the theme it is in.
 *
 * That one fold carries a whole family. Themes declare their paths off it —
 *
 * ```php
 * define( 'ACME_THEME_PATH', get_template_directory() . '/' );
 * define( 'ACME_THEME_INC', ACME_THEME_PATH . 'includes/' );
 * require_once ACME_THEME_INC . 'core.php';
 * ```
 *
 * — so without it, every constant in the chain is unresolvable and so is every
 * include built from one. A real client theme lost nine of its includes to
 * exactly this, which is most of its own code.
 *
 * ## What counts as a theme
 *
 * A path segment matching `wp-content/themes/<name>/` (or `themes/<name>/` at
 * the scan root), which is where WordPress requires themes to live. Read from
 * the scanned file list, never from the filesystem: the resolver answers
 * questions about the code, not about the machine running the scan.
 *
 * A plugin calling `get_template_directory()` gets no answer from the calling
 * file. When the scan holds exactly one theme, that theme is the answer;
 * several themes is genuinely ambiguous and resolves to nothing rather than a
 * guess.
 */
final class ThemeRoots
{
    /**
     * @param list<string> $roots absolute theme root directories, no trailing slash
     */
    private function __construct(private readonly array $roots)
    {
    }

    /**
     * @param list<string> $files absolute paths of every file in the scan
     */
    public static function fromFiles(array $files): self
    {
        $roots = [];

        foreach ($files as $file) {
            if (preg_match('#^(.*/themes/[^/]+)/#', str_replace('\\', '/', $file), $matches) === 1) {
                $roots[$matches[1]] = true;
            }
        }

        return new self(array_keys($roots));
    }

    /**
     * The theme directory `get_template_directory()` would return, seen from
     * this file, or null when there is no unambiguous answer.
     */
    public function forFile(string $file): ?string
    {
        $file = str_replace('\\', '/', $file);

        foreach ($this->roots as $root) {
            if (str_starts_with($file, $root . '/')) {
                return $root;
            }
        }

        return count($this->roots) === 1 ? $this->roots[0] : null;
    }

    public function isEmpty(): bool
    {
        return $this->roots === [];
    }
}
