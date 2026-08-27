<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Taint;

/**
 * Who calls whom, as plain data.
 *
 * The taint engine does not need this — summaries carry the dataflow across a
 * call boundary without anyone having to name the edge. The *authorization*
 * rules do, because the question they ask is reachability rather than dataflow:
 * "somewhere below this AJAX callback, does anything check a capability?"
 *
 * That question used to be answered by looking at the callback's own statements
 * and accepting any call whose name contained `can`, `nonce` or `verify`. It
 * credited `acf_verify_ajax()` for the right reason by accident and
 * `$this->can_haz_cheeseburger()` for no reason at all. Walking real edges
 * credits a helper because of what it actually calls.
 */
final class CallGraph
{
    /**
     * User function keys called by each function key.
     *
     * @var array<string, list<string>>
     */
    private array $edges = [];

    /**
     * Catalogue matcher identities called by each function key — the leaves the
     * walk is looking for.
     *
     * @var array<string, list<string>>
     */
    private array $externals = [];

    /**
     * Every function body the builder walked.
     *
     * Distinct from having edges. A permission callback that is just
     * `return true;` calls nothing at all, and "it has no outgoing edges" is
     * precisely the answer the REST rule needs — not "we have never heard of
     * it", which is what asking about edges alone reported.
     *
     * @var array<string, true>
     */
    private array $known = [];

    /**
     * Function keys whose body contains a call the engine could not resolve.
     *
     * A walk that finds no authorization check but passed through one of these
     * has not proved absence, only failed to find presence. The rules report it
     * differently.
     *
     * @var array<string, true>
     */
    private array $imprecise = [];

    public function addFunction(string $key): void
    {
        $this->known[$key] = true;
    }

    public function addEdge(string $from, string $to): void
    {
        if (! in_array($to, $this->edges[$from] ?? [], true)) {
            $this->edges[$from][] = $to;
        }
    }

    public function addExternal(string $from, string $identity): void
    {
        if (! in_array($identity, $this->externals[$from] ?? [], true)) {
            $this->externals[$from][] = $identity;
        }
    }

    public function markImprecise(string $from): void
    {
        $this->imprecise[$from] = true;
    }

    /**
     * Whether anything reachable from `$key` calls one of `$identities`.
     *
     * Breadth-first with a visited set, so recursion terminates and a diamond
     * is not walked twice. The depth cap is a cost control rather than a
     * correctness one: a capability check ten helpers deep is not something a
     * reviewer would credit either.
     *
     * @param list<string> $identities catalogue matcher identities to look for
     */
    public function reaches(string $key, array $identities, int $maxDepth = 6): bool
    {
        return $this->walk($key, $identities, $maxDepth)['found'];
    }

    /**
     * Whether the walk from `$key` passed through anything unresolved.
     *
     * Only meaningful when {@see reaches()} came back false: it separates "we
     * looked everywhere and there is no check" from "we lost the thread".
     *
     * @param list<string> $identities
     */
    public function walkWasComplete(string $key, array $identities, int $maxDepth = 6): bool
    {
        return $this->walk($key, $identities, $maxDepth)['complete'];
    }

    /**
     * @param list<string> $identities
     *
     * @return array{found: bool, complete: bool}
     */
    private function walk(string $key, array $identities, int $maxDepth): array
    {
        $wanted = array_flip($identities);
        $seen = [$key => true];
        $frontier = [$key];
        $complete = true;

        for ($depth = 0; $depth <= $maxDepth && $frontier !== []; $depth++) {
            $next = [];

            foreach ($frontier as $current) {
                foreach ($this->externals[$current] ?? [] as $identity) {
                    if (isset($wanted[$identity])) {
                        return ['found' => true, 'complete' => true];
                    }
                }

                if (isset($this->imprecise[$current])) {
                    $complete = false;
                }

                foreach ($this->edges[$current] ?? [] as $callee) {
                    if (isset($seen[$callee])) {
                        continue;
                    }

                    $seen[$callee] = true;
                    $next[] = $callee;
                }
            }

            $frontier = $next;
        }

        // Stopping at the cap with work left is not a complete answer either.
        return ['found' => false, 'complete' => $complete && $frontier === []];
    }

    /**
     * @return list<string>
     */
    public function calleesOf(string $key): array
    {
        return $this->edges[$key] ?? [];
    }

    public function knows(string $key): bool
    {
        return isset($this->known[$key]);
    }
}
