<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Registry;

use RuntimeException;

/**
 * A registry that will not load.
 *
 * A typo in a security catalogue silently creates false negatives, so every
 * problem here is fatal and names the file and the key.
 */
final class RegistryException extends RuntimeException
{
    public static function at(string $file, string $context, string $message): self
    {
        return new self(sprintf('%s: %s — %s', $file, $context, $message));
    }
}
