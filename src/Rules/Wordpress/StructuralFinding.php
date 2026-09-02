<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Cfg\SourceMap;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Fingerprint;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Finding\TraceStep;
use Enshrined\WpTaint\Finding\TraceVerb;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use PhpParser\Node;

/**
 * Building a one-step finding from an AST node.
 *
 * The authorization rules each grew their own copy of this, which was tolerable
 * at two rules and is not at five. Nothing here is rule-specific: a node, a
 * sentence about why it is wrong, and the identity the fingerprint keys on.
 */
final class StructuralFinding
{
    public static function at(
        Node $node,
        ParsedFile $file,
        Registry $registry,
        string $ruleId,
        Severity $severity,
        string $description,
        string $identity,
        TaintKind $kind = TaintKind::Authz,
    ): Finding {
        $line = $node->getStartLine();
        $column = self::column($node, $file->sourceMap);
        $snippet = trim($file->sourceMap->line($line));

        $step = new TraceStep(
            TraceVerb::Sink,
            $file->relativePath,
            $line,
            $column,
            null,
            $snippet,
            $description,
            TaintSet::of($kind),
        );

        return new Finding(
            $ruleId,
            $registry->rule($ruleId),
            $severity,
            $kind,
            $file->relativePath,
            $line,
            $column,
            null,
            $registry->ruleMessage($ruleId),
            [$step],
            Fingerprint::compute($ruleId, $file->relativePath, $identity, $snippet),
            false,
            $identity,
        );
    }

    public static function column(Node $node, SourceMap $sourceMap): int
    {
        if (! $node->hasAttribute('startFilePos')) {
            return 0;
        }

        $offset = $node->getAttribute('startFilePos');

        return is_int($offset) ? $sourceMap->positionAt($offset)['column'] : 0;
    }
}
