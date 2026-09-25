<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Which shared entries each function read while it was analysed.
 *
 * The interprocedural loop used to re-analyse every function every round, to
 * settle the handful whose inputs had moved. A function's analysis reads
 * nothing shared except the summary table, the property map and the scope
 * table, so if none of the entries it read last time has changed, running it
 * again would produce exactly what it produced before. This is the record that
 * makes skipping it exact rather than a guess: what was read, not what the
 * call graph predicts will be.
 *
 * Keys are prefixed by table: `s:` a summary, `p:` a property as `class::name`
 * and `p*:` every class's property of that name, `si:`/`so:`/`sk:`/`sg:` a
 * scope's inbound variables, outbound variables, keyed entries and origins.
 */
final class ReadLog
{
    /** The function whose reads are being recorded, or null between functions. */
    public ?string $reader = null;

    /** @var array<string, array<string, true>> function key => entries read */
    private array $reads = [];

    public function record(string $entry): void
    {
        if ($this->reader !== null) {
            $this->reads[$this->reader][$entry] = true;
        }
    }

    /**
     * Start a function afresh: what it reads now replaces what it read before.
     */
    public function begin(string $reader): void
    {
        $this->reader = $reader;
        $this->reads[$reader] = [];
    }

    /**
     * @return array<string, list<string>> function key => entries read
     */
    public function all(): array
    {
        return array_map(array_keys(...), $this->reads);
    }
}
