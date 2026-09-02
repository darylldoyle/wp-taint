<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Finding;

/**
 * A finding the author marked reviewed with a matching `phpcs:ignore`.
 *
 * A suppression comment is not proof the code is safe; it is proof the author
 * looked. So it does not delete the finding, it moves it to {@see
 * Severity::Notice} and records why here, for the trace to explain. The
 * `--no-phpcs-suppressions` flag turns this off, for auditing code whose
 * author's judgement you do not share.
 */
final class Acknowledgement
{
    public function __construct(
        public readonly string $sniff,
        public readonly ?string $reason = null,
    ) {
    }
}
