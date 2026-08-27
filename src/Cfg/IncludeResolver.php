<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Support\PathHelper;
use Enshrined\WpTaint\Taint\ValueResolver;
use PHPCfg\Op;

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
        $candidates = $this->values->strings($op->expr);

        if ($candidates === [] || count($candidates) > self::MAX_TARGETS) {
            return [];
        }

        $base = dirname($includingFile);
        $resolved = [];

        foreach ($candidates as $candidate) {
            foreach ($this->expand($candidate, $base) as $path) {
                if (isset($this->known[$path]) && ! in_array($this->known[$path], $resolved, true)) {
                    $resolved[] = $this->known[$path];
                }
            }
        }

        sort($resolved);

        return $resolved;
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
