<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use PHPCfg\AbstractVisitor;
use PHPCfg\Block;
use PHPCfg\Func;
use PHPCfg\Op;
use PHPCfg\Operand;

/**
 * php-cfg's Simplifier, with trivial-phi removal made linear.
 *
 * Copied from ircmaxell/php-cfg 0.8 (PHPCfg\Visitor\Simplifier), MIT licence,
 * copyright 2015 Anthony Ferrara. Everything but replaceVariables() and the
 * index it reads is upstream's code, unchanged, so a diff against the vendored
 * file shows the whole of what differs.
 *
 * It exists because upstream's replaceVariables() re-walks the function for
 * every phi it removes. On the client scan that prompted this, the simplifier
 * was 117 seconds of a 145-second parse. The graphs it produces are compared
 * against upstream's by `tools/compare-simplifier.php`, which must report no
 * difference over the corpus before this is changed.
 */
final class Simplifier extends AbstractVisitor
{
    protected \SplObjectStorage $removed;

    protected \SplObjectStorage $recursionProtection;

    protected \SplObjectStorage $trivialPhiCandidates;

    /**
     * Every op in a block reachable from the function's entry, and the block
     * each phi belongs to. Built once per function before trivial phis go.
     *
     * @var \SplObjectStorage<Op, Block>
     */
    private \SplObjectStorage $liveOps;

    public function enterFunc(Func $func): void
    {
        $this->removed = new \SplObjectStorage();
        $this->recursionProtection = new \SplObjectStorage();
    }

    public function leaveFunc(Func $func): void
    {
        // Remove trivial PHI functions
        if ($func->cfg) {
            $this->trivialPhiCandidates = new \SplObjectStorage();
            $this->removeTrivialPhi($func->cfg);
        }
    }

    public function enterOp(Op $op, Block $block): void
    {
        if ($this->recursionProtection->contains($op)) {
            return;
        }
        $this->recursionProtection->attach($op);
        foreach ($op->getSubBlocks() as $name => $targets) {
            /** @var Block $block */
            if (! is_array($targets)) {
                $targets = [$targets];
            }
            $results = [];
            foreach ($targets as $key => $target) {
                $results[$key] = $target;
                if (! $target || ! isset($target->children[0]) || ! $target->children[0] instanceof Op\Stmt\Jump) {
                    continue;
                }
                if ($this->removed->contains($target)) {
                    // short circuit
                    $results[$key] = $target->children[0]->target;
                    if (! in_array($block, $target->children[0]->target->parents, true)) {
                        $target->children[0]->target->parents[] = $block;
                    }

                    continue;
                }

                if (! isset($target->children[0]) || ! $target->children[0] instanceof Op\Stmt\Jump) {
                    continue;
                }

                // First, optimize the child:
                $this->enterOp($target->children[0], $target);

                if ($target->children[0]->target === $target) {
                    // Prevent killing infinite tight loops
                    continue;
                }

                if (count($target->phi) > 0) {
                    // It's a phi block, we can't reassign it
                    // Handle the VERY specific case of a double jump with a phi node on both ends'

                    $found = [];
                    foreach ($target->phi as $phi) {
                        $foundPhi = null;
                        foreach ($target->children[0]->target->phi as $subPhi) {
                            if ($subPhi->hasOperand($phi->result)) {
                                $foundPhi = $subPhi;

                                break;
                            }
                        }
                        if (! $foundPhi) {
                            // At least one phi is not directly used
                            continue 2;
                        }
                        $found[] = [$phi, $foundPhi];
                    }
                    // If we get here, we can actually remove the phi node and teh jump
                    foreach ($found as $nodes) {
                        $phi = $nodes[0];
                        $foundPhi = $nodes[1];
                        $foundPhi->removeOperand($phi->result);
                        foreach ($phi->vars as $var) {
                            $foundPhi->addOperand($var);
                        }
                    }
                    $target->phi = [];
                }
                $this->removed->attach($target);
                $target->dead = true;

                // Remove the target from the list of parents
                $k = array_search($target, $target->children[0]->target->parents, true);
                unset($target->children[0]->target->parents[$k]);
                $target->children[0]->target->parents = array_values($target->children[0]->target->parents);

                if (! in_array($block, $target->children[0]->target->parents, true)) {
                    $target->children[0]->target->parents[] = $block;
                }

                $results[$key] = $target->children[0]->target;
            }

            if (!is_array($op->{$name})) {
                $op->{$name} = $results[0];
            } else {
                $op->{$name} = $results;
            }
        }
        $this->recursionProtection->detach($op);
    }

    private function removeTrivialPhi(Block $block): void
    {
        $this->indexLiveOps($block);

        $toReplace = new \SplObjectStorage();
        $replaced = new \SplObjectStorage();
        $toReplace->attach($block);
        while ($toReplace->count() > 0) {
            foreach ($toReplace as $block) {
                $toReplace->detach($block);
                $replaced->attach($block);
                foreach ($block->phi as $key => $phi) {
                    if ($this->tryRemoveTrivialPhi($phi, $block)) {
                        unset($block->phi[$key]);
                    }
                }
                foreach ($block->children as $child) {
                    foreach ($child->getSubBlocks() as $subBlocks) {
                        if (! is_array($subBlocks)) {
                            if ($subBlocks === null) {
                                continue;
                            }
                            $subBlocks = [$subBlocks];
                        }
                        foreach ($subBlocks as $subBlock) {
                            if (! $replaced->contains($subBlock)) {
                                $toReplace->attach($subBlock);
                            }
                        }
                    }
                }
            }
        }
        while ($this->trivialPhiCandidates->count() > 0) {
            foreach ($this->trivialPhiCandidates as $phi) {
                $block = $this->trivialPhiCandidates[$phi];
                $this->trivialPhiCandidates->detach($phi);
                if ($this->tryRemoveTrivialPhi($phi, $block)) {
                    $key = array_search($phi, $block->phi, true);
                    if ($key !== false) {
                        unset($block->phi[$key]);
                    }
                }
            }
        }
    }

    private function tryRemoveTrivialPhi(Op\Phi $phi, Block $block): bool
    {
        if (count($phi->vars) > 1) {
            return false;
        }
        if (count($phi->vars) === 0) {
            // shouldn't happen except in unused variables
            $var = new Operand\Temporary($phi->result->original);
        } else {
            $var = $phi->vars[0];
        }
        // Remove Phi!
        $this->replaceVariables($phi->result, $var, $block);

        return true;
    }

    /**
     * Replace `$from` with `$to` wherever it is read or written.
     *
     * Upstream walks every block reachable from the phi's block and visits
     * every op in them, once per trivial phi removed. That is phi count times
     * op count, and on real WordPress files it was most of the parse time:
     * 89 million calls to replaceOpVariable() over 1,337 files.
     *
     * The operand already lists the ops that read and write it, so only those
     * are visited. Restricted to ops in live blocks, which is what the walk
     * could reach: in SSA a use is dominated by its definition, so every use
     * the walk found is in this set, and a use in a dead block is one the walk
     * never touched.
     */
    private function replaceVariables(Operand $from, Operand $to, Block $block): void
    {
        $seen = new \SplObjectStorage();

        // Copied first: removeOperand() below edits $from->usages.
        foreach ([...$from->usages, ...$from->ops] as $op) {
            if ($seen->contains($op) || ! $this->liveOps->contains($op)) {
                continue;
            }

            $seen->attach($op);

            if ($op instanceof Op\Phi) {
                if ($op->hasOperand($from)) {
                    // Since we're removing from the phi, it may become trivial
                    $this->trivialPhiCandidates[$op] = $this->liveOps[$op];
                    $op->removeOperand($from);
                    $op->addOperand($to);
                }

                continue;
            }

            $this->replaceOpVariable($from, $to, $op);
        }
    }

    /**
     * The same walk upstream's replaceVariables() did, done once.
     */
    private function indexLiveOps(Block $entry): void
    {
        $this->liveOps = new \SplObjectStorage();
        $pending = [$entry];
        $visited = new \SplObjectStorage();

        while ($pending !== []) {
            $block = array_pop($pending);

            if ($visited->contains($block)) {
                continue;
            }

            $visited->attach($block);

            foreach ($block->phi as $phi) {
                $this->liveOps[$phi] = $block;
            }

            foreach ($block->children as $child) {
                $this->liveOps[$child] = $block;

                foreach ($child->getSubBlocks() as $subBlocks) {
                    foreach (is_array($subBlocks) ? $subBlocks : [$subBlocks] as $subBlock) {
                        if ($subBlock !== null && ! $visited->contains($subBlock)) {
                            $pending[] = $subBlock;
                        }
                    }
                }
            }

            // Catch and finally blocks are reached through the try's catch
            // target, not through any op's sub-blocks. Upstream's walk never
            // followed that edge, which is how a use inside a catch kept
            // pointing at a phi that had been removed.
            if ($block->catchTarget !== null) {
                foreach ($block->catchTarget->catches as $catch) {
                    $pending[] = $catch['block'];
                }

                if ($block->catchTarget->finally !== null) {
                    $pending[] = $block->catchTarget->finally;
                }
            }
        }
    }

    private function replaceOpVariable(Operand $from, Operand $to, Op $op): void
    {
        foreach ($op->getVariableNames() as $name) {
            if (null === $op->{$name}) {
                continue;
            }
            if (is_array($op->{$name})) {
                // SIGH, PHP won't let me do this directly (parses as $op->($name[$key]))
                $result = $op->{$name};
                $new = [];
                foreach ($result as $key => $value) {
                    if ($value === $from) {
                        $new[$key] = $to;
                        if ($op->isWriteVariable($name)) {
                            $to->addWriteOp($op);
                        } else {
                            $to->addUsage($op);
                        }
                    } else {
                        $new[$key] = $value;
                    }
                }
                $op->{$name} = $new;
            } elseif ($op->{$name} === $from) {
                $op->{$name} = $to;
                if ($op->isWriteVariable($name)) {
                    $to->addWriteOp($op);
                } else {
                    $to->addUsage($op);
                }
            }
        }
    }
}
