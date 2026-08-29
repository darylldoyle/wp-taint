<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * Works out which file an `include` or `require` actually loads.
 *
 * 5,996 include sites in the corpus. This is the pattern WordPress themes are
 * made of, and until now none of it was followed.
 *
 * Path resolution is constant folding over the shapes WordPress really uses:
 *
 * ```php
 * require_once __DIR__ . '/inc/settings.php';
 * include dirname( __FILE__ ) . '/templates/header.php';
 * require ACME_PLUGIN_DIR . 'admin/view.php';
 * include plugin_dir_path( __FILE__ ) . 'partials/' . $slug . '.php';
 * ```
 *
 * The magic constants fold at parse time and the named ones come from the
 * constant table, so by the time an operand reaches here it is usually already
 * a literal or a concatenation of them. A variable in the middle produces a set,
 * and every member that exists on disk is a candidate.
 *
 * ## Only files already in the scan
 *
 * A resolved path is looked up in the set of files being analysed rather than on
 * disk. Including something outside the scan would mean parsing and summarising
 * a file the user did not ask for, which is `--include-path`'s job, not this
 * one. It also keeps the resolver deterministic: two machines with the same
 * checkout resolve the same set, whatever else is lying around their
 * filesystems.
 */
final class IncludeResolver
{
    /**
     * Candidate paths per include, beyond which the site is left unresolved.
     *
     * A slug in an include path is usually one of a handful of templates. If it
     * expands to more than this, the value is genuinely dynamic and joining the
     * scope of every candidate would connect variables that never meet.
     */
    private const MAX_TARGETS = 8;

    /** @var array<string, string> normalised absolute path => relative path */
    private array $known = [];

    /**
     * @param list<string> $files absolute paths of every file in the scan
     */
    public function __construct(
        private readonly ValueResolver $values,
        array $files,
        private readonly string $projectRoot,
        private readonly ?ThemeRoots $themes = null,
    ) {
        foreach ($files as $path) {
            $real = realpath($path);

            if ($real !== false) {
                $this->known[$real] = PathHelper::relative($real, $this->projectRoot);
            }
        }
    }

    /**
     * Relative paths of the files an include site can load.
     *
     * Empty when the path could not be resolved, or resolved to nothing in the
     * scan. The caller records that rather than treating it as "includes
     * nothing".
     *
     * @return list<string>
     */
    public function resolve(Op\Expr\Include_ $op, string $includingFile): array
    {
        return $this->resolvePath($op->expr, $includingFile);
    }

    /**
     * The files a path operand can name.
     *
     * @return list<string>
     */
    public function resolvePath(Operand $path, string $includingFile): array
    {
        $candidates = $this->values->strings($path);

        if ($candidates === [] || count($candidates) > self::MAX_TARGETS) {
            return [];
        }

        $base = dirname($includingFile);
        $resolved = [];

        foreach ($candidates as $candidate) {
            foreach ($this->expand($candidate, $base) as $absolute) {
                if (isset($this->known[$absolute]) && ! in_array($this->known[$absolute], $resolved, true)) {
                    $resolved[] = $this->known[$absolute];
                }
            }
        }

        sort($resolved);

        return $resolved;
    }

    /**
     * Candidate files for `get_template_part( $slug, $name )`.
     *
     * WordPress tries `{$slug}-{$name}.php` and then `{$slug}.php`, searching
     * the child theme before the parent. Only the shapes present in the scan
     * matter, so both candidates are offered and whichever exists wins — a
     * theme that ships only the general template still resolves.
     *
     * A slug that will not fold to a string returns nothing, and the caller
     * records the site as unresolved rather than guessing at a filename.
     *
     * @param list<string> $slugs
     * @param list<string> $names
     *
     * @return list<string>
     */
    public function resolveTemplate(array $slugs, array $names, string $callingFile): array
    {
        if ($slugs === []) {
            return [];
        }

        $candidates = [];

        foreach ($slugs as $slug) {
            $slug = trim($slug, '/');

            if ($slug === '') {
                continue;
            }

            // The variant first, exactly as the template hierarchy orders it.
            foreach ($names as $name) {
                $name = trim($name);

                if ($name !== '') {
                    $candidates[] = $slug . '-' . $name . '.php';
                }
            }

            $candidates[] = $slug . '.php';
        }

        if (count($candidates) > self::MAX_TARGETS) {
            return [];
        }

        $base = dirname($callingFile);
        $resolved = [];

        foreach ($candidates as $candidate) {
            foreach ($this->themeRoots($base) as $root) {
                $path = realpath($root . '/' . $candidate);

                if ($path !== false && isset($this->known[$path]) && ! in_array($this->known[$path], $resolved, true)) {
                    $resolved[] = $this->known[$path];
                }
            }
        }

        sort($resolved);

        return $resolved;
    }

    /**
     * Directories a template slug could be relative to.
     *
     * A template path is relative to the theme root, which is not necessarily
     * the scan root — someone scanning a whole `wp-content` has several. Walking
     * up from the calling file to the nearest directory holding `style.css` or
     * `functions.php` finds it; the scan root and the calling file's own
     * directory are offered as well, because a theme under analysis is often
     * scanned directly and a partial often sits beside its caller.
     *
     * @return list<string>
     */
    private function themeRoots(string $base): array
    {
        $roots = [$base];
        $directory = $base;

        for ($depth = 0; $depth < 8; $depth++) {
            if (is_file($directory . '/style.css') || is_file($directory . '/functions.php')) {
                $roots[] = $directory;

                // A child theme's template hierarchy falls back to its parent:
                // `get_template_part( 'partials/card' )` loads the parent's
                // partials/card.php when the child has none, so the parent is
                // a lookup root too. Which theme is the parent comes from
                // style.css, the same way WordPress reads it.
                if ($this->themes !== null) {
                    // Realpathed, because the roots were built from the file
                    // list this class also realpaths, and /tmp vs /private/tmp
                    // is exactly the mismatch that silently loses the parent.
                    $real = realpath($directory);
                    $roots = [...$roots, ...$this->themes->parentsOf($real === false ? $directory : $real)];
                }

                break;
            }

            $parent = dirname($directory);

            if ($parent === $directory || ! str_starts_with($parent, $this->projectRoot)) {
                break;
            }

            $directory = $parent;
        }

        $roots[] = $this->projectRoot;

        return array_values(array_unique($roots));
    }

    /**
     * A written path, as the absolute paths it could mean.
     *
     * PHP resolves a relative include against the include path and then the
     * calling file's directory. Only the second is modelled: the first is
     * runtime configuration the analysis cannot see, and guessing at it would
     * connect files that never meet.
     *
     * @return list<string>
     */
    private function expand(string $candidate, string $base): array
    {
        if ($candidate === '') {
            return [];
        }

        $paths = [];

        if (str_starts_with($candidate, '/')) {
            $paths[] = $candidate;
        } else {
            $paths[] = $base . '/' . $candidate;
            $paths[] = $this->projectRoot . '/' . $candidate;
        }

        $real = [];

        foreach ($paths as $path) {
            $resolved = realpath($path);

            if ($resolved !== false) {
                $real[] = $resolved;
            }
        }

        return $real;
    }
}
