<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

/**
 * A finding the author suppressed with a matching `phpcs:ignore`.
 *
 * A suppression comment proves the author deliberately silenced that sniff, not
 * that the code was reviewed and found safe. So it does not delete the finding,
 * it reduces it to {@see Severity::Notice} and records why here, for the trace
 * to explain. The original severity is kept so the reader can see what was
 * downgraded and by how much. The `--no-phpcs-suppressions` flag turns this
 * off, for auditing code whose author's judgement you do not share.
 */
final class Acknowledgement
{
    public function __construct(
        public readonly string $sniff,
        public readonly ?string $reason = null,
        /**
         * The severity the finding carried before it was reduced to a notice.
         * Null when unknown, so a reader is never shown a fabricated one.
         */
        public readonly ?Severity $originalSeverity = null,
    ) {
    }
}
