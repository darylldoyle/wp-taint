<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

final class Explanation
{
    /**
     * @param list<string> $observations
     */
    public function __construct(
        public readonly string $file,
        public readonly int $line,
        public readonly string $snippet,
        public readonly TaintSet $taint,
        public readonly ?TaintKind $kind,
        public readonly bool $lineWasAnalysed,
        public readonly array $observations,
    ) {
    }

    public function render(): string
    {
        $out = sprintf("%s:%d\n\n", $this->file, $this->line);

        if ($this->snippet !== '') {
            $out .= '  ' . $this->snippet . "\n\n";
        }

        if (! $this->lineWasAnalysed) {
            return $out . "  No analysable operation was found on this line.\n\n"
                . "  The line may be a comment, a declaration, or inside a file that failed to parse.\n"
                . "  Run: wp-taint scan <path> --parse-report\n";
        }

        $out .= sprintf("  Taint at this point: %s\n\n", $this->taint->describe());

        if ($this->kind !== null) {
            $out .= $this->taint->has($this->kind)
                ? sprintf("  A finding IS expected here for kind=%s.\n\n", $this->kind->value)
                : sprintf("  No finding is expected here for kind=%s.\n\n", $this->kind->value);
        }

        if ($this->observations === []) {
            return $out . "  No tainted value reaches this location, and nothing was abandoned on the way.\n";
        }

        $out .= "  Why:\n";

        foreach ($this->observations as $observation) {
            $out .= '    - ' . wordwrap($observation, 88, "\n      ") . "\n";
        }

        return $out;
    }
}
