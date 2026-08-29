<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

/**
 * Which theme a scanned file belongs to, and how the themes relate.
 *
 * `get_stylesheet_directory()` and `get_template_directory()` are runtime
 * questions — "where is the active theme", "where is its parent" — with static
 * answers whenever the scan can see the themes involved. Themes declare their
 * paths off these —
 *
 * ```php
 * define( 'ACME_THEME_PATH', get_template_directory() . '/' );
 * define( 'ACME_THEME_INC', ACME_THEME_PATH . 'includes/' );
 * require_once ACME_THEME_INC . 'core.php';
 * ```
 *
 * — so without the fold, every constant in the chain is unresolvable and so is
 * every include built from one.
 *
 * ## What counts as a theme
 *
 * A path segment matching `themes/<name>/`, which is where WordPress requires
 * themes to live, read from the scanned file list.
 *
 * ## Parent and child
 *
 * A child theme names its parent in `style.css`:
 *
 * ```
 * Template: acme-parent
 * ```
 *
 * That header is how WordPress itself resolves the pair, so it is how this
 * does: `get_stylesheet_directory()` is the file's own theme,
 * `get_template_directory()` is the declared parent when the scan holds it.
 * The one filesystem read this class performs is that header, from the
 * `style.css` of a theme the user pointed the scan at — project content, the
 * same standing as the PHP beside it.
 *
 * ## A file outside every theme
 *
 * A plugin runs under whichever theme is active, and any scanned theme could
 * be it. The answer is every candidate, the same union a hook name that
 * resolves to two strings gets — never a guess at one, and never nothing when
 * the set is known and finite.
 */
final class ThemeRoots
{
    /** How much of a style.css to read looking for the Template header. */
    private const HEADER_BYTES = 8192;

    /**
     * @param list<string>          $roots   theme root directories, no trailing slash
     * @param array<string, string> $parents child root => parent root, both in the scan
     * @param array<string, true>   $known   every scanned file, forward-slashed
     */
    private function __construct(
        private readonly array $roots,
        private readonly array $parents,
        private readonly array $known,
    ) {
    }

    /**
     * @param list<string> $files absolute paths of every file in the scan
     */
    public static function fromFiles(array $files): self
    {
        $roots = [];
        $known = [];

        foreach ($files as $file) {
            $file = str_replace('\\', '/', $file);
            $known[$file] = true;

            if (preg_match('#^(.*/themes/[^/]+)/#', $file, $matches) === 1) {
                $roots[$matches[1]] = true;
            }
        }

        $roots = array_keys($roots);
        $parents = [];

        foreach ($roots as $root) {
            $slug = self::declaredParent($root);

            if ($slug === null) {
                continue;
            }

            $parent = dirname($root) . '/' . $slug;

            if (in_array($parent, $roots, true)) {
                $parents[$root] = $parent;
            }
        }

        return new self($roots, $parents, $known);
    }

    /**
     * The `Template:` header of a theme's style.css, when it has one.
     */
    private static function declaredParent(string $root): ?string
    {
        $stylesheet = $root . '/style.css';

        if (! is_file($stylesheet)) {
            return null;
        }

        $header = file_get_contents($stylesheet, length: self::HEADER_BYTES);

        if ($header === false) {
            return null;
        }

        if (preg_match('/^[ \t\/*#@]*Template:\s*([\w-]+)/mi', $header, $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * Where `get_stylesheet_directory()` points, seen from this file.
     *
     * @return list<string>
     */
    public function stylesheetRootsFor(string $file): array
    {
        $own = $this->owningRoot($file);

        return $own !== null ? [$own] : $this->roots;
    }

    /**
     * Where `get_template_directory()` points, seen from this file.
     *
     * The file's own theme's declared parent when the scan holds it; the theme
     * itself when it declares none. A child whose parent is *not* in the scan
     * folds to nothing, because every path built on the answer would name files
     * that are not there.
     *
     * @return list<string>
     */
    public function templateRootsFor(string $file): array
    {
        $own = $this->owningRoot($file);

        if ($own !== null) {
            return $this->templateRootOf($own);
        }

        $all = [];

        foreach ($this->roots as $root) {
            foreach ($this->templateRootOf($root) as $candidate) {
                $all[$candidate] = true;
            }
        }

        return array_keys($all);
    }

    /**
     * `get_theme_file_path( $relative )`: the child's copy when it exists, the
     * parent's otherwise — the override order WordPress uses.
     *
     * @return list<string>
     */
    public function themeFilePathsFor(string $file, string $relative): array
    {
        $relative = ltrim($relative, '/');
        $paths = [];

        foreach ($this->stylesheetRootsFor($file) as $child) {
            $candidate = $child . '/' . $relative;

            if (isset($this->known[$candidate])) {
                $paths[$candidate] = true;

                continue;
            }

            foreach ($this->templateRootOf($child) as $parent) {
                $paths[$parent . '/' . $relative] = true;
            }
        }

        return array_keys($paths);
    }

    /**
     * The parent of a theme root, for template-hierarchy fallback.
     *
     * @return list<string>
     */
    public function parentsOf(string $root): array
    {
        $parent = $this->parents[$root] ?? null;

        return $parent === null ? [] : [$parent];
    }

    /**
     * @return list<string>
     */
    private function templateRootOf(string $root): array
    {
        if (isset($this->parents[$root])) {
            return [$this->parents[$root]];
        }

        // No declared parent: the theme is its own template root. A declared
        // parent the scan does not hold means the true answer is a directory
        // with no files here, and folding to the child instead would be wrong
        // in a way that looks resolved.
        return self::declaredParent($root) === null ? [$root] : [];
    }

    private function owningRoot(string $file): ?string
    {
        $file = str_replace('\\', '/', $file);

        foreach ($this->roots as $root) {
            if (str_starts_with($file, $root . '/')) {
                return $root;
            }
        }

        return null;
    }

    public function isEmpty(): bool
    {
        return $this->roots === [];
    }
}
