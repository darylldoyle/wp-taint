<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Support;

/**
 * Runs PHP's cycle collector when the heap has grown, not when its root buffer
 * fills.
 *
 * PHP collects cycles every time ten thousand possible roots have gathered, and
 * each run walks what those roots reach. A scan's control flow graphs are one
 * large web of cycles, and a run reaches a great deal of it. Measured on one
 * large site's reference trees, the collector took 58 of the first
 * 85 seconds of parsing and freed almost nothing, because a held graph is not
 * garbage. With a memory budget, a dropped graph is garbage, but the collector
 * still ran hundreds of times to find it.
 *
 * So the scan turns automatic collection off and calls {@see tick()} between
 * units of work: a file parsed, a body handed out. A tick collects once the
 * heap has grown by {@see $step} since the last collection.
 *
 * The step is 1GB, not less. Each collection also walks the cached graphs the
 * analysis has just touched, so its cost is mostly the size of what is live,
 * and a small step pays that cost too often. At 256MB, a 40-tree scan spent
 * 266 of 406 seconds of reference parsing in the collector; at 1GB, 112 of
 * 273. The price is up to a gigabyte of garbage waiting for the next run. Nothing the
 * analysis computes depends on when memory is freed, only on what is alive,
 * and a tick never runs while a unit of work is half done.
 */
final class CycleCollector
{
    public const DEFAULT_STEP = 1024 * 1024 * 1024;

    private int $collectAt;

    private bool $wasEnabled = false;

    public function __construct(private readonly int $step = self::DEFAULT_STEP)
    {
        $this->collectAt = memory_get_usage() + $step;
    }

    /**
     * Take over from the automatic collector until {@see stop()}.
     */
    public function start(): void
    {
        $this->wasEnabled = gc_enabled();
        gc_disable();
        $this->collectAt = memory_get_usage() + $this->step;
    }

    /**
     * Collect and hand back to the automatic collector, if it was on.
     */
    public function stop(): void
    {
        gc_collect_cycles();

        if ($this->wasEnabled) {
            gc_enable();
        }
    }

    public function tick(): void
    {
        if (memory_get_usage() < $this->collectAt) {
            return;
        }

        gc_collect_cycles();
        $this->collectAt = memory_get_usage() + $this->step;
    }
}
