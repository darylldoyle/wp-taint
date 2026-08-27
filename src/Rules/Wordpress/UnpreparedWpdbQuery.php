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
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Taint\TaintKind;
use Enshrined\WpTaint\Taint\TaintSet;
use PhpParser\Node;

/**
 * A variable interpolated or concatenated into a `$wpdb` query.
 *
 * This deliberately overlaps the taint rule. Taint analysis reports the flows it
 * can follow; this reports the *shape*, which catches queries built from values
 * the dataflow engine could not reach — an unresolvable helper, a dynamic call,
 * a value from a file we did not scan.
 *
 * When both fire on the same line the taint finding wins, because it carries a
 * real source-to-sink trace. {@see \Enshrined\WpTaint\Finding\FindingCollection::withoutSupersededStructuralFindings()}
 * does that de-duplication.
 *
 * `{$wpdb->prefix}` and the other table-name properties are excluded. They are
 * the standard idiom and flagging them would bury the real findings.
 */
final class UnpreparedWpdbQuery implements StructuralRule
{
    private const RULE = 'wp.sqli.unprepared-query';

    private const QUERY_METHODS = ['query', 'get_results', 'get_var', 'get_row', 'get_col'];

    public function id(): string
    {
        return self::RULE;
    }

    /**
     * @return list<Finding>
     */
    public function analyse(ParsedFile $file, Registry $registry, RuleContext $context): array
    {
        $findings = [];

        foreach (AstHelper::findAll($file->ast, Node\Expr\MethodCall::class) as $call) {
            if (! $call instanceof Node\Expr\MethodCall || ! $call->name instanceof Node\Identifier) {
                continue;
            }

            if (! in_array(strtolower($call->name->toString()), self::QUERY_METHODS, true)) {
                continue;
            }

            if (! $this->isDatabaseHandle($call->var)) {
                continue;
            }

            $argument = AstHelper::argument($call, 0);

            if ($argument === null || ! $this->hasUnsafeInterpolation($argument, $registry)) {
                continue;
            }

            // The dataflow engine already accounted for every contributor to
            // this query and found it clean — an absint(), an esc_sql(), a
            // cast. Reporting the shape anyway would be a false positive on
            // the safest idioms in the ecosystem.
            if ($context->originsAreResolved($file->relativePath, $call->getStartLine())) {
                continue;
            }

            $findings[] = $this->finding($call, $file, $registry);
        }

        return $findings;
    }

    private function isDatabaseHandle(Node\Expr $receiver): bool
    {
        if ($receiver instanceof Node\Expr\Variable && is_string($receiver->name)) {
            return in_array(strtolower($receiver->name), ['wpdb', 'db'], true);
        }

        if ($receiver instanceof Node\Expr\PropertyFetch && $receiver->name instanceof Node\Identifier) {
            return in_array(strtolower($receiver->name->toString()), ['wpdb', 'db'], true);
        }

        return false;
    }

    /**
     * True when the query string embeds something other than literals and
     * known-safe database identifiers.
     */
    private function hasUnsafeInterpolation(Node\Expr $query, Registry $registry): bool
    {
        if ($query instanceof Node\Scalar\String_) {
            return false;
        }

        if ($query instanceof Node\Scalar\InterpolatedString) {
            foreach ($query->parts as $part) {
                if ($part instanceof Node\InterpolatedStringPart) {
                    continue;
                }

                if (! $this->isSafeFragment($part, $registry)) {
                    return true;
                }
            }

            return false;
        }

        if ($query instanceof Node\Expr\BinaryOp\Concat) {
            return $this->hasUnsafeInterpolation($query->left, $registry)
                || $this->hasUnsafeInterpolation($query->right, $registry);
        }

        // A call to prepare() is the correct shape; the taint engine handles
        // whether its format string is literal.
        if ($query instanceof Node\Expr\MethodCall && $query->name instanceof Node\Identifier) {
            return strtolower($query->name->toString()) !== 'prepare';
        }

        return ! $this->isSafeFragment($query, $registry);
    }

    private function isSafeFragment(Node $fragment, Registry $registry): bool
    {
        if ($fragment instanceof Node\Scalar\String_ || $fragment instanceof Node\Scalar\Int_) {
            return true;
        }

        if ($fragment instanceof Node\Expr\ConstFetch || $fragment instanceof Node\Expr\ClassConstFetch) {
            return true;
        }

        if ($fragment instanceof Node\Expr\PropertyFetch && $fragment->name instanceof Node\Identifier) {
            return $this->isDatabaseHandle($fragment->var)
                && in_array($fragment->name->toString(), $registry->safeDatabaseIdentifiers(), true);
        }

        return false;
    }

    private function finding(Node\Expr\MethodCall $call, ParsedFile $file, Registry $registry): Finding
    {
        $line = $call->getStartLine();
        $column = self::column($call, $file->sourceMap);
        $snippet = trim($file->sourceMap->line($line));

        $method = $call->name instanceof Node\Identifier ? $call->name->toString() : 'query';
        $identity = 'wpdb::' . $method;

        $step = new TraceStep(
            TraceVerb::Sink,
            $file->relativePath,
            $line,
            $column,
            null,
            $snippet,
            sprintf(
                'A variable is interpolated into the query passed to %s(). Taint analysis could not prove where the '
                    . 'value comes from, but the shape is unsafe regardless.',
                $identity,
            ),
            TaintSet::of(TaintKind::Sql),
        );

        return new Finding(
            self::RULE,
            $registry->rule(self::RULE),
            Severity::High,
            TaintKind::Sql,
            $file->relativePath,
            $line,
            $column,
            null,
            $registry->ruleMessage(self::RULE),
            [$step],
            Fingerprint::compute(self::RULE, $file->relativePath, $identity, $snippet),
        );
    }

    private static function column(Node $node, SourceMap $sourceMap): int
    {
        if (! $node->hasAttribute('startFilePos')) {
            return 0;
        }

        $offset = $node->getAttribute('startFilePos');

        return is_int($offset) ? $sourceMap->positionAt($offset)['column'] : 0;
    }
}
