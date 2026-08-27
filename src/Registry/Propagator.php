<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

/**
 * Something that passes taint through unchanged.
 *
 * The `note` is load-bearing. `wp_unslash()` lives here, and the note is what
 * stops the next person moving it into `[[sanitizers]]` — the single most
 * common misunderstanding in WordPress code review.
 */
final class Propagator
{
    public function __construct(
        public readonly Matcher $matcher,
        public readonly ArgumentSelector $arguments,
        public readonly ?string $note = null,
    ) {
    }
}
