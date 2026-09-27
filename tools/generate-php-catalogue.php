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
 * ## Classes that hold text
 *
 * A few of PHP's classes hold text: the DOM, SimpleXML, the SPL containers and
 * exceptions. A method of one that returns text returns its arguments' and its
 * object's, and a method that keeps what it is given, `loadHTML()` or
 * `offsetSet()`, puts its arguments into the object. `new` with one of those
 * constructors makes an object that holds its arguments. Every other class
 * holds no text of its own.
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
    'filter_var' => 'What comes back depends on the filter constant. php-core.toml models it.',
    'filter_var_array' => 'What comes back depends on the filter constants. php-core.toml models it.',
    'filter_input' => 'A request source whose result depends on the filter constant. php-core.toml models it.',
    'filter_input_array' => 'A request source whose result depends on the filter constants. php-core.toml models it.',
];

const NOT_TEXT = ['int', 'float', 'bool', 'false', 'true', 'null', 'void', 'never', 'callable'];

/**
 * PHP's classes whose objects hold text: what goes in comes back out. A
 * subclass PHP defines counts too. Every other class of PHP's holds no text of
 * its own, so a `DateTime` made from a request value formats to digits.
 */
const TEXT_CLASSES = [
    'DOMNode', 'DOMNodeList', 'DOMNamedNodeMap', 'DOMXPath',
    'SimpleXMLElement',
    'ArrayObject', 'ArrayIterator', 'SplFixedArray', 'SplDoublyLinkedList', 'SplObjectStorage', 'SplHeap',
    'SplPriorityQueue',
    'Exception', 'Error',
];

/**
 * Methods that keep what they are given, so the object holds it afterwards.
 * A subclass inherits its parent's.
 */
const STORES = [
    'DOMNode' => ['appendChild', 'insertBefore', 'replaceChild'],
    'DOMDocument' => ['loadHTML', 'loadXML', 'append', 'prepend', 'replaceChildren'],
    'DOMElement' => [
        '__construct', 'setAttribute', 'setAttributeNS', 'setAttributeNode', 'setAttributeNodeNS', 'append',
        'prepend', 'replaceChildren', 'before', 'after', 'replaceWith', 'insertAdjacentElement',
        'insertAdjacentText',
    ],
    'DOMCharacterData' => ['__construct', 'appendData', 'insertData', 'replaceData', 'before', 'after', 'replaceWith'],
    'DOMAttr' => ['__construct'],
    'DOMProcessingInstruction' => ['__construct'],
    'DOMEntityReference' => ['__construct'],
    'DOMDocumentFragment' => ['appendXML', 'append', 'prepend', 'replaceChildren'],
    'DOMXPath' => ['__construct'],
    'SimpleXMLElement' => ['__construct', 'addChild', 'addAttribute'],
    'ArrayObject' => ['__construct', 'offsetSet', 'append', 'exchangeArray', 'unserialize', '__unserialize'],
    'ArrayIterator' => ['__construct', 'offsetSet', 'append', 'unserialize', '__unserialize'],
    'SplFixedArray' => ['offsetSet', '__unserialize'],
    'SplDoublyLinkedList' => ['add', 'push', 'unshift', 'offsetSet', 'unserialize', '__unserialize'],
    'SplQueue' => ['enqueue'],
    'SplObjectStorage' => ['attach', 'offsetSet', 'addAll', 'setInfo', 'unserialize', '__unserialize'],
    'SplHeap' => ['insert'],
    'SplPriorityQueue' => ['insert'],
    'Exception' => ['__construct'],
    'Error' => ['__construct'],
];

/**
 * Whether a class is one of PHP's that hold text, or a subclass PHP defines.
 */
function holdsTextClass(string $class): bool
{
    foreach (TEXT_CLASSES as $textClass) {
        if (is_a($class, $textClass, true)) {
            return true;
        }
    }

    return false;
}

/**
 * Whether a method keeps what it is given, on its own class or a parent.
 */
function stores(string $class, string $method): bool
{
    foreach (STORES as $owner => $methods) {
        if (is_a($class, $owner, true) && in_array($method, $methods, true)) {
            return true;
        }
    }

    return false;
}

/**
 * Whether a declared return names one of PHP's classes that hold text.
 */
function returnsTextClass(?ReflectionType $type): bool
{
    $parts = $type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType
        ? $type->getTypes()
        : ($type === null ? [] : [$type]);

    foreach ($parts as $part) {
        if ($part instanceof ReflectionNamedType && ! $part->isBuiltin() && holdsTextClass($part->getName())) {
            return true;
        }
    }

    return false;
}

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

    // `simplexml_load_string()` returns an object that holds the text it read.
    if (! holdsText($returns, classesCount: false) && ! returnsTextClass($returns)) {
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
    $lines[] = sprintf('function = %s', tomlString($name));
    $lines[] = sprintf('returns = %s', tomlString($returns === null ? 'mixed' : (string) $returns));
    $lines[] = sprintf('args = [%s]', implode(', ', $arguments));

    if ($from !== null) {
        $lines[] = sprintf('args_from = %d', $from);
    }

    $lines[] = '';
    $written++;
}

// Methods of the classes that hold text.
$classes = array_values(array_filter(
    get_declared_classes(),
    static fn (string $class): bool => (new ReflectionClass($class))->isInternal()
        && in_array(strtolower((string) (new ReflectionClass($class))->getExtensionName()), EXTENSIONS, true)
        && holdsTextClass($class),
));
sort($classes);

foreach ($classes as $class) {
    $methods = (new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC);
    usort($methods, static fn (ReflectionMethod $a, ReflectionMethod $b): int => strcmp($a->getName(), $b->getName()));

    foreach ($methods as $method) {
        $name = $method->getName();
        $keeps = stores($class, $name);
        $returns = $method->getReturnType() ?? $method->getTentativeReturnType();
        $returnsText = $name !== '__construct' && holdsText($returns, classesCount: true);

        if (! $keeps && ! $returnsText) {
            continue;
        }

        $arguments = [];
        $from = null;

        foreach ($method->getParameters() as $position => $parameter) {
            if (! holdsText($parameter->getType(), classesCount: true)) {
                continue;
            }

            if ($parameter->isVariadic()) {
                $from = $position;

                continue;
            }

            $arguments[] = $position;
        }

        // A constructor that keeps nothing of its arguments makes an object
        // that holds nothing.
        if ($name === '__construct' && ($arguments === [] && $from === null)) {
            continue;
        }

        $lines[] = '[[internal]]';
        $lines[] = sprintf('class = %s', tomlString($class));
        $lines[] = sprintf('%s = %s', $method->isStatic() ? 'static_method' : 'method', tomlString($name));
        $lines[] = sprintf('returns = %s', tomlString($returns === null ? 'mixed' : (string) $returns));
        $lines[] = sprintf('args = [%s]', implode(', ', $arguments));

        if ($from !== null) {
            $lines[] = sprintf('args_from = %d', $from);
        }

        if (! $returnsText && $name !== '__construct') {
            $lines[] = 'returns_text = false';
        }

        if ($returnsText && ! $method->isStatic()) {
            $lines[] = 'receiver = true';
        }

        if ($keeps) {
            $lines[] = 'stores = true';
        }

        $lines[] = '';
        $written++;
    }
}

file_put_contents(OUTPUT, implode("\n", $lines));

printf("Wrote %d entries to registries/php-generated.toml. Skipped on purpose:\n", $written);

foreach (SKIPPED as $name => $reason) {
    printf("  %-20s %s\n", $name, $reason);
}

/**
 * A TOML basic string. Namespaced names hold backslashes.
 */
function tomlString(string $value): string
{
    return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
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
