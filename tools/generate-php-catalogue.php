<?php

/**
 * Regenerates `registries/php-generated.toml` from PHP's own declarations.
 *
 * A PHP function the catalogue did not list returned clean, whatever it was.
 * `explode( ',', $_GET['ids'] )` came back clean, and so did `array_pop()`,
 * `strstr()`, `dirname()` and 300 more that the corpus calls 25,000 times.
 * Listing them by hand one at a time is how that happened.
 *
 * Reflection already says what each one takes and returns. This writes one
 * entry for every function declared to return something that can hold text,
 * and names the parameters that can hold text. The engine reads an entry only
 * for a call no hand-written section models, so every entry in php-core.toml
 * wins: a hash, a type name or an escaper is modelled there.
 *
 * ## What counts as text
 *
 * `string`, `array`, `mixed`, no declared type, `iterable`, `object`, or a
 * union with one of those. A class type is an object too, for a parameter:
 * `iterator_to_array()` reads what the object holds. For a return, a class
 * alone is not listed. `date_create()` returns a `DateTime`, which holds no
 * text of its own, and methods are not modelled here.
 *
 * `int`, `float`, `bool`, `null` and the like are not text. An `int` length or
 * a `bool` flag cannot put characters of its own into the result, so a
 * function that returns only those stays clean, and such a parameter is not
 * listed. `callable` is not text either: `usort()`'s callback is code.
 *
 * ## Why a file, not reflection at scan time
 *
 * A scan should answer the same on every PHP version and with any set of
 * extensions. Reflection at scan time would make `mb_strtolower()` clean on a
 * PHP without mbstring. The file records the PHP that wrote it; regenerate it
 * on a PHP with the extensions the scanned code uses.
 *
 * Usage: php tools/generate-php-catalogue.php
 */

declare(strict_types=1);

const OUTPUT = __DIR__ . '/../registries/php-generated.toml';

/**
 * The extensions whose functions are written: PHP's own, and those WordPress
 * requires or recommends. Others, a profiler or a database driver no WordPress
 * site uses, would only make the file depend on the machine that wrote it.
 */
const EXTENSIONS = [
    'bcmath', 'calendar', 'core', 'ctype', 'curl', 'date', 'dom', 'exif', 'fileinfo', 'filter', 'ftp', 'gd',
    'gettext', 'gmp', 'hash', 'iconv', 'intl', 'json', 'libxml', 'mbstring', 'mysqli', 'openssl', 'pcre', 'pdo',
    'random', 'session', 'simplexml', 'sodium', 'spl', 'standard', 'tokenizer', 'xml', 'xmlreader',
    'xmlwriter', 'zip', 'zlib',
];

/**
 * Functions left out on purpose, with the reason.
 */
const SKIPPED = [
    'filter_var' => 'What comes back depends on the filter constant. Modelled by filter.',
    'filter_var_array' => 'What comes back depends on the filter constants. Modelled by filter.',
    'filter_input' => 'A request source whose result depends on the filter constant. Modelled by filter.',
    'filter_input_array' => 'A request source whose result depends on the filter constants. Modelled by filter.',
];

const NOT_TEXT = ['int', 'float', 'bool', 'false', 'true', 'null', 'void', 'never', 'callable'];

/**
 * Whether a declared type can hold text, and so pass some on.
 */
function holdsText(?ReflectionType $type, bool $classesCount): bool
{
    if ($type === null) {
        return true;
    }

    $parts = $type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType
        ? $type->getTypes()
        : [$type];

    foreach ($parts as $part) {
        if (! $part instanceof ReflectionNamedType) {
            return true;
        }

        $name = strtolower($part->getName());

        if (in_array($name, NOT_TEXT, true)) {
            continue;
        }

        if ($part->isBuiltin() || $classesCount) {
            return true;
        }
    }

    return false;
}

$lines = [
    '# Generated from PHP\'s own declarations by tools/generate-php-catalogue.php.',
    '# Do not edit by hand: regenerate it.',
    '#',
    '# One entry for each PHP function declared to return something that can hold',
    '# text, naming the parameters that can hold text. The engine reads an entry',
    '# only for a call no other section models, so php-core.toml wins.',
    '#',
    sprintf('# Written by PHP %s with: %s.', PHP_VERSION, implode(', ', sortedExtensions())),
    '',
    '[meta]',
    'name = "php-generated"',
    'description = "PHP functions by declared type"',
    '',
];

$written = 0;
$functions = get_defined_functions()['internal'];
sort($functions);

foreach ($functions as $name) {
    if (isset(SKIPPED[$name])) {
        continue;
    }

    $reflection = new ReflectionFunction($name);

    if (! in_array(strtolower((string) $reflection->getExtensionName()), EXTENSIONS, true)) {
        continue;
    }

    $returns = $reflection->getReturnType() ?? $reflection->getTentativeReturnType();

    if (! holdsText($returns, classesCount: false)) {
        continue;
    }

    $arguments = [];
    $from = null;

    foreach ($reflection->getParameters() as $position => $parameter) {
        if (! holdsText($parameter->getType(), classesCount: true)) {
            continue;
        }

        if ($parameter->isVariadic()) {
            $from = $position;

            continue;
        }

        $arguments[] = $position;
    }

    // Nothing that can hold text goes in, so nothing that can comes out that
    // the arguments chose. `random_bytes( 16 )`, `getcwd()`.
    if ($arguments === [] && $from === null) {
        continue;
    }

    $lines[] = '[[internal]]';
    $lines[] = sprintf('function = "%s"', $name);
    $lines[] = sprintf('returns = "%s"', $returns === null ? 'mixed' : (string) $returns);
    $lines[] = sprintf('args = [%s]', implode(', ', $arguments));

    if ($from !== null) {
        $lines[] = sprintf('args_from = %d', $from);
    }

    $lines[] = '';
    $written++;
}

file_put_contents(OUTPUT, implode("\n", $lines));

printf("Wrote %d functions to registries/php-generated.toml. Skipped on purpose:\n", $written);

foreach (SKIPPED as $name => $reason) {
    printf("  %-20s %s\n", $name, $reason);
}

/**
 * @return list<string>
 */
function sortedExtensions(): array
{
    $extensions = array_values(array_intersect(array_map('strtolower', get_loaded_extensions()), EXTENSIONS));
    sort($extensions);

    return $extensions;
}
