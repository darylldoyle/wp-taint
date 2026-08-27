<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * A function that loads a theme template by name.
 *
 * ```php
 * get_template_part( 'template-parts/content', get_post_type(), [ 'title' => $title ] );
 * get_header( 'shop' );
 * ```
 *
 * The idiomatic form in a theme, and the shape a theme-heavy codebase is made
 * of. `include` following covers a plugin; this covers the other half.
 *
 * ## Not an include
 *
 * The distinction matters and it is easy to get wrong. A plain `include` shares
 * the includer's entire variable scope. `get_template_part()` does not: it goes
 * through `load_template()`, so the template body sees globals and the `$args`
 * array, and *not* the caller's locals.
 *
 * Modelling it as an include would connect every variable in the calling file to
 * every template it loads. That is over-approximation of the worst kind — it
 * would manufacture findings in exactly the files themes put their output in.
 */
final class TemplateLoader
{
    public function __construct(
        public readonly Matcher $matcher,
        /**
         * Argument holding the slug, when the function takes one.
         *
         * `get_header()` does not: its slug is fixed, and only the variant is
         * passed.
         */
        public readonly ?int $slugArgument,
        /** A fixed slug, for `get_header()` and friends. */
        public readonly ?string $slug,
        /** Argument holding the variant: `get_header( 'shop' )` → `header-shop.php`. */
        public readonly ?int $nameArgument,
        /** Argument holding the `$args` array the template can read. */
        public readonly ?int $argsArgument,
        /** Argument holding an already-resolved path, for `load_template()`. */
        public readonly ?int $pathArgument,
        public readonly ?string $note = null,
    ) {
    }
}
