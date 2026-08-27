<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * What to assume about a call the engine could not resolve.
 *
 * There is no correct answer, only a choice about which way to be wrong, and
 * the choice belongs to whoever is reading the output. Every finding produced
 * under an assumption is marked imprecise so it can be filtered back out.
 */
enum DynamicCallPolicy: string
{
    /**
     * The call returns nothing tainted.
     *
     * A documented false negative. Correct when the unresolvable calls in a
     * codebase are container lookups and dependency-injection plumbing, which
     * genuinely do not carry request data.
     */
    case Clean = 'clean';

    /**
     * The arguments flow to the return value; nothing new is introduced.
     *
     * The default. An unresolved call is nearly always a call to code in the
     * same project, and code in the same project transforms its arguments
     * rather than conjuring request data out of nothing. Assuming a callee
     * launders taint is the assumption least likely to be true.
     */
    case Propagate = 'propagate';

    /**
     * The return value is fully tainted, regardless of the arguments.
     *
     * An upper bound on what the engine might be missing. Noisy on purpose, and
     * the right setting when auditing the auditor.
     */
    case Tainted = 'tainted';

    public function describe(): string
    {
        return match ($this) {
            self::Clean => 'its return value is assumed clean',
            self::Propagate => 'its arguments are assumed to flow to its return value',
            self::Tainted => 'its return value is assumed fully tainted',
        };
    }
}
