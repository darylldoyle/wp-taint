<?php

/**
 * Lists the WordPress functions that return a value a third party can rewrite.
 *
 * Escaping is called *late* escaping because it has to be the last thing that
 * happens to a value. Anything afterwards is another chance to undo it, and in
 * WordPress the commonest "anything afterwards" is not a visible
 * `apply_filters()` call — it is an ordinary-looking core function with a filter
 * inside it:
 *
 * ```php
 * echo get_the_title( $id );          // 'the_title' runs inside
 * echo wp_trim_words( $escaped );     // 'wp_trim_words' runs inside
 * ```
 *
 * Guessing at that by name — anything starting `wp_` or `get_` — would be a
 * heuristic. This is a fact, and it is derivable: parse a WordPress checkout and
 * find every function whose *return value* comes out of `apply_filters()`.
 *
 * Of 4,272 core functions, 933 mention a filter and **524 return one**. The
 * difference matters: a function that filters something internal and returns
 * something else does not hand an attacker the value you are about to print.
 *
 * What counts is not whether the `return` statement *is* an `apply_filters()`
 * call, but whether the value being returned has been through one anywhere on
 * the way:
 *
 *   $a = apply_filters( 'x', $p );
 *   $b = strtoupper( $a );
 *   return $b;                       // still filtered
 *
 * So this runs a small fixed point over the body: a variable is filtered if it
 * is assigned from an `apply_filters()` call or from anything mentioning an
 * already-filtered variable, repeated until nothing changes. A function counts
 * when a `return` mentions a filtered variable or calls a filter directly.
 *
 * Pattern-matching the two obvious spellings instead found 524 functions; this
 * finds the ones where the filter and the return are several statements apart,
 * which is most of how core is actually written.
 *
 * Deliberately conservative in one direction: a filter whose result never
 * reaches the return does not count. `$flag = apply_filters( 'should_x', true );
 * if ( $flag ) { return $safe; }` hands nobody your value.
 *
 * Usage:
 *   php tools/generate-filterable-catalogue.php /path/to/wordpress [--check]
 *
 * The path is any WordPress checkout; `wp-includes` and `wp-admin` are read.
 * Regenerate when WordPress does something interesting, and commit the diff.
 */

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

/**
 * Calls whose result is built from their arguments.
 *
 * Passing a filtered value to a function does not generally make the result
 * filtered. `wp_update_comment()` hands `$data` to `$wpdb->update()` and
 * returns the row count, which is a number and not your string — treating that
 * as filtered put the plugin pinned to zero findings onto the board.
 *
 * These are the exceptions: string builders, where the result genuinely is the
 * arguments. `_navigation_markup()` ends `return sprintf( $template, ... )`
 * with a filtered `$template`, and a plugin hooking it controls the markup.
 */
const PASS_THROUGH = [
    'sprintf', 'vsprintf', 'implode', 'join', 'str_replace', 'str_ireplace', 'strtr',
    'preg_replace', 'trim', 'ltrim', 'rtrim', 'substr', 'strtolower', 'strtoupper',
    'ucfirst', 'ucwords', 'nl2br', 'wordwrap', 'strip_tags', 'html_entity_decode',
    'htmlspecialchars_decode', 'stripslashes', 'wp_unslash', 'array_map', 'reset', 'current',
];

const OUTPUT = __DIR__ . '/../registries/wordpress-filterable.toml';

$arguments = array_values(array_filter(array_slice($argv, 1), static fn (string $a): bool => $a !== '--check'));
$check = in_array('--check', $argv, true);
$root = $arguments[0] ?? null;

if ($root === null || ! is_dir($root)) {
    fwrite(STDERR, "Usage: php tools/generate-filterable-catalogue.php /path/to/wordpress [--check]\n");

    exit(1);
}

$directories = array_values(array_filter(
    [$root . '/wp-includes', $root . '/wp-admin'],
    static fn (string $path): bool => is_dir($path),
));

if ($directories === []) {
    fwrite(STDERR, sprintf("%s does not look like a WordPress checkout: no wp-includes.\n", $root));

    exit(1);
}

$parser = (new ParserFactory())->createForNewestSupportedVersion();
$finder = new NodeFinder();
$names = [];
$scanned = 0;

foreach ($directories as $directory) {
    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $contents = file_get_contents($file->getPathname());

        if ($contents === false) {
            continue;
        }

        try {
            $ast = $parser->parse($contents) ?? [];
        } catch (Throwable) {
            continue;
        }

        foreach ($finder->findInstanceOf($ast, Node\Stmt\Function_::class) as $function) {
            $scanned++;

            $params = filteredReturnParameters($function, $finder);

            if ($params !== null) {
                $names[strtolower($function->name->toString())] = $params;
            }
        }
    }
}

ksort($names);

$version = versionOf($root);
$lines = [
    '# WordPress functions whose return value has been through a filter.',
    '#',
    '# Generated by tools/generate-filterable-catalogue.php. Do not edit by hand:',
    '# `composer filterable:check` fails when this file and the generator disagree.',
    '#',
    '# A value these return is not yours. Any plugin on the site may hook the',
    '# filter inside and return something else, so escaping done *before* one of',
    '# these calls no longer holds at the point of output. See TaintKind::EscapeVoided.',
    '#',
    sprintf('# Derived from WordPress %s: %d functions read, %d listed.', $version, $scanned, count($names)),
    '',
    '[meta]',
    'name = "wordpress-filterable"',
    'description = "Core functions that return a filtered value, so they void earlier escaping"',
    '',
];

foreach ($names as $name => $params) {
    $lines[] = '[[filterable]]';
    $lines[] = sprintf('function = "%s"', $name);
    $lines[] = sprintf('params = [%s]', implode(', ', $params));
    $lines[] = '';
}

$encoded = implode("\n", $lines);

if (! $check) {
    file_put_contents(OUTPUT, $encoded);
    printf("Wrote registries/wordpress-filterable.toml: %d of %d functions.\n", count($names), $scanned);

    exit(0);
}

$stored = is_file(OUTPUT) ? file_get_contents(OUTPUT) : false;

if (($stored === false ? '' : $stored) === $encoded) {
    printf("Filterable catalogue is up to date.\n");

    exit(0);
}

fwrite(STDERR, "registries/wordpress-filterable.toml does not match the generator.\n"
    . "Run: composer filterable:generate\n");

exit(1);

/**
 * Which parameters does this function's filtered return value come from?
 *
 * Null when the return has not been through a filter at all. An empty list when
 * it has, but out of something other than a parameter — `get_the_title( $id )`
 * filters a title it fetched from the database, and the `$id` you passed is not
 * what comes back.
 *
 * That distinction is the difference between a finding and a false positive.
 * Akismet does this:
 *
 *     $comment['comment_author_url'] = esc_url( $_POST['url'] );
 *     print( wp_update_comment( $comment ) );
 *
 * The escaped value goes in; a row count comes out. Voiding on "any escaped
 * argument" reported it, and the plugin pinned to zero findings is exactly
 * where that showed up.
 *
 * @return list<int>|null
 */
function filteredReturnParameters(Node\Stmt\Function_ $function, NodeFinder $finder): ?array
{
    $body = $function->stmts ?? [];

    $parameters = [];

    foreach ($function->params as $index => $param) {
        if ($param->var instanceof Node\Expr\Variable && is_string($param->var->name)) {
            $parameters[$param->var->name] = $index;
        }
    }

    /** @var array<string, true> $filtered */
    $filtered = [];

    /** @var array<string, array<int, true>> $origins variable => parameter indices it derives from */
    $origins = [];

    foreach ($parameters as $name => $index) {
        /** @var array<int, true> $seed */
        $seed = [$index => true];
        $origins[$name] = $seed;
    }

    // Assignments in source order, iterated to a fixed point so that a filtered
    // value reaching the return through three intermediate variables still
    // counts. Cheap: core functions are short and this converges in one or two
    // rounds.
    /** @var list<Node\Expr\Assign|Node\Expr\AssignOp> $assignments */
    $assignments = [
        ...$finder->findInstanceOf($body, Node\Expr\Assign::class),
        ...$finder->findInstanceOf($body, Node\Expr\AssignOp::class),
    ];

    do {
        $changed = false;

        foreach ($assignments as $assign) {
            if (! $assign->var instanceof Node\Expr\Variable || ! is_string($assign->var->name)) {
                continue;
            }

            if (isset($filtered[$assign->var->name])) {
                continue;
            }

            // Union rather than replace, and compare on sorted keys. Rebuilding
            // the set each round in whatever order the finder walked produced
            // arrays that were equal in content and unequal to `!==`, so the
            // fixed point never settled and the generator ran forever.
            $inherited = $origins[$assign->var->name] ?? [];

            foreach (array_keys(originsOf([$assign->expr], $finder, $origins)) as $index) {
                if (! isset($inherited[$index])) {
                    $inherited[$index] = true;
                    $changed = true;
                }
            }

            $origins[$assign->var->name] = $inherited;

            if (callsFilter([$assign->expr], $finder) || mentionsFiltered([$assign->expr], $finder, $filtered)) {
                $filtered[$assign->var->name] = true;
                $changed = true;
            }
        }
    } while ($changed);

    $found = null;

    foreach ($finder->findInstanceOf($body, Node\Stmt\Return_::class) as $return) {
        if ($return->expr === null) {
            continue;
        }

        if (! callsFilter([$return->expr], $finder) && ! mentionsFiltered([$return->expr], $finder, $filtered)) {
            continue;
        }

        $found = [...($found ?? []), ...array_keys(originsOf([$return->expr], $finder, $origins))];
    }

    if ($found === null) {
        return null;
    }

    $found = array_values(array_unique($found));
    sort($found);

    return $found;
}

/**
 * Parameter indices every variable in these nodes derives from.
 *
 * @param array<array-key, Node>              $nodes
 * @param array<string, array<int, true>>     $origins
 *
 * @return array<int, true>
 */
function originsOf(array $nodes, NodeFinder $finder, array $origins): array
{
    $found = [];

    foreach (valueBearingVariables($nodes) as $name) {
        foreach (array_keys($origins[$name] ?? []) as $index) {
            $found[$index] = true;
        }
    }

    return $found;
}

/**
 * @param array<array-key, Node>  $nodes
 * @param array<string, true>     $filtered
 */
function mentionsFiltered(array $nodes, NodeFinder $finder, array $filtered): bool
{
    foreach (valueBearingVariables($nodes) as $name) {
        if (isset($filtered[$name])) {
            return true;
        }
    }

    return false;
}

/**
 * Variables whose value can reach the result of these expressions.
 *
 * Descends through concatenation, ternaries and array access, and into call
 * arguments only for {@see PASS_THROUGH}. Everything else is opaque: a value
 * handed to a function is not the value that comes back.
 *
 * @param array<array-key, Node> $nodes
 *
 * @return list<string>
 */
function valueBearingVariables(array $nodes): array
{
    $found = [];

    foreach ($nodes as $node) {
        if (! $node instanceof Node) {
            continue;
        }

        if ($node instanceof Node\Expr\Variable) {
            if (is_string($node->name)) {
                $found[] = $node->name;
            }

            continue;
        }

        $opaque = ($node instanceof Node\Expr\FuncCall && ! isPassThrough($node))
            || $node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\StaticCall
            || $node instanceof Node\Expr\New_;

        if ($opaque) {
            continue;
        }

        // getSubNodeNames() is how php-parser exposes a node's children
        // generically, and reading them back is necessarily dynamic.
        foreach ($node->getSubNodeNames() as $name) {
            /** @var mixed $child */
            $child = $node->{(string) $name}; // @phpstan-ignore property.dynamicName
            $children = is_array($child) ? $child : [$child];
            $found = [...$found, ...valueBearingVariables(array_filter(
                $children,
                static fn (mixed $item): bool => $item instanceof Node,
            ))];
        }
    }

    return $found;
}

function isPassThrough(Node\Expr\FuncCall $call): bool
{
    if (! $call->name instanceof Node\Name) {
        return false;
    }

    $name = strtolower($call->name->toString());

    return in_array($name, PASS_THROUGH, true) || str_starts_with($name, 'apply_filters');
}

/**
 * @param array<array-key, Node> $nodes
 */
function callsFilter(array $nodes, NodeFinder $finder): bool
{
    foreach ($finder->findInstanceOf($nodes, Node\Expr\FuncCall::class) as $call) {
        if (! $call->name instanceof Node\Name) {
            continue;
        }

        if (str_starts_with(strtolower($call->name->toString()), 'apply_filters')) {
            return true;
        }
    }

    return false;
}

function versionOf(string $root): string
{
    $file = $root . '/wp-includes/version.php';
    $contents = is_file($file) ? file_get_contents($file) : false;

    if ($contents !== false && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $contents, $matches) === 1) {
        return $matches[1];
    }

    return 'unknown';
}
