<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Rules\Wordpress;

use Enshrined\WpTaint\Cfg\ParsedFile;
use Enshrined\WpTaint\Finding\Finding;
use Enshrined\WpTaint\Finding\Severity;
use Enshrined\WpTaint\Registry\Registry;
use Enshrined\WpTaint\Rules\AstHelper;
use Enshrined\WpTaint\Rules\RuleContext;
use Enshrined\WpTaint\Rules\StructuralRule;
use Enshrined\WpTaint\Taint\MarkupPosition;
use Enshrined\WpTaint\Taint\TaintKind;
use PhpParser\Node;

/**
 * An escaper is present, and it is the wrong one for where the value lands.
 *
 * ```php
 * echo '<script>var x = "' . esc_html( $v ) . '";</script>';   // ";alert(1);//
 * printf( '<a href="%s">x</a>', esc_attr( $url ) );            // javascript:...
 * printf( '<div data-v=%s></div>', esc_html( $v ) );           // x onmouseover=
 * ```
 *
 * Every one of those has a visible `esc_*` call and every one is exploitable.
 * An analyser that asks "was an escaper applied" answers yes to all three,
 * which is why this is a separate question from whether escaping happened at
 * all.
 *
 * ## Why this is structural rather than dataflow
 *
 * The context is not a property of the value; it is a property of the literal
 * text around the hole the value goes into. `esc_attr()` is right in a quoted
 * attribute, wrong in an `href`, and wrong again in an unquoted one — same
 * value, same escaper, three answers. That is a question about the string
 * being built, which the AST states directly and the CFG has dissolved.
 *
 * ## What it looks at
 *
 * `echo`, `print`, and `printf`/`sprintf`, where a literal part of the string
 * establishes the context and an adjacent part is a call to a known escaper.
 * Both spellings matter: the context can sit in a concatenated literal or in a
 * format string with the escaper in the arguments.
 *
 * Anything it cannot read — a context built from a variable, a placeholder it
 * cannot map to an argument — is left alone. A wrong answer here accuses
 * correct code of a subtle bug, which is worse than saying nothing.
 */
final class WrongContextEscape implements StructuralRule
{
    private const RULE = 'wp.xss.wrong-context-escape';

    /**
     * What each escaper is for.
     *
     * `esc_url_raw` is absent from the URL set and handled as its own case,
     * because "it is for storage, not output" is a style rule and this rule
     * reports security. Both variants run the same filter, and the difference
     * between them is one line of WordPress:
     *
     *     if ( 'display' === $_context ) {
     *         $url = wp_kses_normalize_entities( $url );
     *         $url = str_replace( '&amp;', '&#038;', $url );
     *         $url = str_replace( "'", '&#039;', $url );
     *     }
     *
     * Everything that matters here happens before it. The character filter
     * strips `"`, `<`, `>`, backtick and space in both contexts, and the scheme
     * allowlist rejects `javascript:` in both. Only the apostrophe survives —
     * so `href="<?php echo esc_url_raw( $u ); ?>"` cannot be broken out of, and
     * `href='...'` can. WP Super Cache writes the first shape 32 times and was
     * told all 32 were wrong.
     */
    private const HTML_ESCAPERS = ['esc_html', 'esc_html__', 'esc_html_e', 'esc_html_x', 'wp_kses', 'wp_kses_post'];

    /**
     * The subset of HTML escapers that run `_wp_specialchars( $string, ENT_QUOTES )`.
     *
     * These encode both `"` and `'`, so a value they escape cannot break out of
     * a quoted attribute — `<div data-x="<?php echo esc_html( $v ); ?>">` is not
     * a breakout, and reporting it as one accuses correct code. `wp_kses` and
     * `wp_kses_post` are deliberately excluded: they pass markup through and can
     * emit quotes inside the value, so they are not attribute-safe.
     */
    private const QUOTE_ENCODING_ESCAPERS = ['esc_html', 'esc_html__', 'esc_html_e', 'esc_html_x'];

    /** Escapers that reduce their argument to an integer, which no context can break out of. */
    private const INTEGER_ESCAPERS = ['absint', 'intval'];

    private const ATTR_ESCAPERS = [
        'esc_attr', 'esc_attr__', 'esc_attr_e', 'esc_attr_x',
        'sanitize_html_class', 'sanitize_key', 'sanitize_title', 'absint', 'intval',
    ];

    private const URL_ESCAPERS = ['esc_url'];

    private const JS_ESCAPERS = ['esc_js', 'wp_json_encode', 'json_encode'];

    /**
     * The JSON pair, apart from esc_js().
     *
     * json_encode() escapes for a JavaScript value position and nothing else:
     * `<` comes through intact, and both quote characters are JSON syntax it
     * must emit. That makes it right inside a <script> block and wrong in HTML
     * text (a live `<img onerror=…>` needs no closing tag), wrong in a quoted
     * attribute (the JSON's own quotes end it), and wrong in an event handler
     * for the same reason. esc_js() is different: it entity-encodes `<` and
     * `"`, which is exactly the attribute case it was built for.
     */
    private const JSON_ENCODERS = ['wp_json_encode', 'json_encode'];

    /** Attributes whose value is a URL, where only URL escaping protects the scheme. */
    private const URL_ATTRIBUTES = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'cite', 'longdesc'];

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
        $this->bindings = $this->singleBindings($file);

        foreach ($this->outputs($file) as [$node, $parts]) {
            $mismatch = $this->firstMismatch($parts);

            if ($mismatch === null) {
                continue;
            }

            [$escaper, $wanted, $where] = $mismatch;

            $findings[] = StructuralFinding::at(
                $node,
                $file,
                $registry,
                self::RULE,
                Severity::High,
                sprintf(
                    '%s() does not protect a value landing %s, where %s. An escaper is present, so '
                        . 'a check that only asks whether one was called reports nothing here.',
                    $escaper,
                    $where,
                    $wanted,
                ),
                $escaper,
                TaintKind::Html,
            );
        }

        return $findings;
    }

    /**
     * Output statements, decomposed into literal text and escaper calls in order.
     *
     * @return list<array{0: Node, 1: list<array{text: ?string, escaper: ?string, literal: bool}>}>
     */
    private function outputs(ParsedFile $file): array
    {
        $found = [];

        foreach (AstHelper::findAll($file->ast(), Node\Stmt\Echo_::class) as $echo) {
            if (! $echo instanceof Node\Stmt\Echo_) {
                continue;
            }

            $parts = [];

            foreach ($echo->exprs as $expr) {
                $parts = [...$parts, ...$this->flatten($expr)];
            }

            $found[] = [$echo, $parts];
        }

        foreach (AstHelper::findAll($file->ast(), Node\Expr\FuncCall::class) as $call) {
            if (! $call instanceof Node\Expr\FuncCall) {
                continue;
            }

            $name = AstHelper::functionName($call);

            if ($name !== 'printf' && $name !== 'sprintf' && $name !== 'vprintf') {
                continue;
            }

            $parts = $this->fromFormat($call);

            if ($parts !== []) {
                $found[] = [$call, $parts];
            }
        }

        return $found;
    }

    /**
     * The one expression each variable name is bound to in this file, when it
     * is bound exactly once.
     *
     * Any second write — another assignment, `.=`, a reference — or any other
     * construct that binds the name (a parameter, a `foreach`, a closure
     * `use`, destructuring, `global`, `static`, `catch`) drops the name from
     * the map. File-wide rather than scope-aware on purpose: a name reused
     * across two functions disqualifies itself, which only ever costs an
     * opportunity, never invents a context that is not there.
     *
     * @var array<string, Node\Expr>
     */
    private array $bindings = [];

    /**
     * @return array<string, Node\Expr>
     */
    private function singleBindings(ParsedFile $file): array
    {
        $assigned = [];
        $disqualified = [];

        foreach (AstHelper::findAll($file->ast(), Node\Expr\Assign::class) as $assign) {
            if (! $assign instanceof Node\Expr\Assign) {
                continue;
            }

            if ($assign->var instanceof Node\Expr\Variable && is_string($assign->var->name)) {
                $name = $assign->var->name;
                isset($assigned[$name]) ? $disqualified[$name] = true : $assigned[$name] = $assign->expr;

                continue;
            }

            // Destructuring binds every name inside it.
            foreach (AstHelper::findAll([$assign->var], Node\Expr\Variable::class) as $variable) {
                if ($variable instanceof Node\Expr\Variable && is_string($variable->name)) {
                    $disqualified[$variable->name] = true;
                }
            }
        }

        foreach (
            [
            Node\Expr\AssignOp::class,
            Node\Expr\AssignRef::class,
            Node\Param::class,
            Node\Stmt\Foreach_::class,
            Node\ClosureUse::class,
            Node\Stmt\Global_::class,
            Node\Stmt\Static_::class,
            Node\Stmt\Catch_::class,
            ] as $construct
        ) {
            foreach (AstHelper::findAll($file->ast(), $construct) as $node) {
                foreach (AstHelper::findAll([$node], Node\Expr\Variable::class) as $variable) {
                    if ($variable instanceof Node\Expr\Variable && is_string($variable->name)) {
                        $disqualified[$variable->name] = true;
                    }
                }
            }
        }

        return array_diff_key($assigned, $disqualified);
    }

    /**
     * A concatenation, flattened left to right into text and escaper calls.
     *
     * A variable bound exactly once in the file folds to what it was bound to,
     * so a context assembled a line earlier is still judged:
     *
     *     $html = '<a href="' . esc_attr( $url ) . '">go</a>';
     *     echo $html;
     *
     * @return list<array{text: ?string, escaper: ?string, literal: bool}>
     */
    private function flatten(Node\Expr $expr, int $depth = 0): array
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return [...$this->flatten($expr->left, $depth), ...$this->flatten($expr->right, $depth)];
        }

        if ($expr instanceof Node\Scalar\String_) {
            return [['text' => $expr->value, 'escaper' => null, 'literal' => false]];
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            $parts = [];

            foreach ($expr->parts as $part) {
                $parts = [...$parts, ...(
                    $part instanceof Node\InterpolatedStringPart
                        ? [['text' => $part->value, 'escaper' => null, 'literal' => false]]
                        : $this->flatten($part, $depth)
                )];
            }

            return $parts;
        }

        if ($expr instanceof Node\Expr\Variable && is_string($expr->name) && $depth < 3) {
            $bound = $this->bindings[$expr->name] ?? null;

            if ($bound !== null) {
                return $this->flatten($bound, $depth + 1);
            }
        }

        $escaper = $expr instanceof Node\Expr\FuncCall ? AstHelper::functionName($expr) : null;

        return [['text' => null, 'escaper' => $escaper, 'literal' => $this->wrapsSafeLiteral($expr)]];
    }

    /**
     * `printf( '<a href="%s">', esc_attr( $url ) )`: the format supplies the
     * context and the arguments supply the escapers.
     *
     * Only string specifiers are mapped — a numeric or padded one cannot carry
     * a breakout. `%s` maps sequentially and `%1$s` maps to its named
     * argument; a format mixing the two spellings is left alone, because PHP's
     * sequencing rules for the mix are not something to guess at. A format
     * held in a once-bound variable folds first, so
     * `$tpl = '<a href="%s">'; printf( $tpl, esc_attr( $u ) )` is judged.
     *
     * @return list<array{text: ?string, escaper: ?string, literal: bool}>
     */
    private function fromFormat(Node\Expr\FuncCall $call): array
    {
        $arguments = $call->getArgs();
        $format = ($arguments[0]->value ?? null);

        if ($format instanceof Node\Expr\Variable && is_string($format->name)) {
            $format = $this->bindings[$format->name] ?? null;
        }

        if (! $format instanceof Node\Scalar\String_) {
            return [];
        }

        $chunks = preg_split('/(%(?:\d+\$)?s)/', $format->value, -1, PREG_SPLIT_DELIM_CAPTURE);
        $chunks = $chunks === false ? [] : $chunks;

        $bare = false;
        $positional = false;

        foreach ($chunks as $chunk) {
            if ($chunk === '%s') {
                $bare = true;
            } elseif (preg_match('/^%\d+\$s$/', $chunk) === 1) {
                $positional = true;
            }
        }

        if ($bare && $positional) {
            return [];
        }

        $parts = [];
        $index = 1;

        foreach ($chunks as $chunk) {
            $argumentIndex = null;

            if ($chunk === '%s') {
                $argumentIndex = $index++;
            } elseif (preg_match('/^%(\d+)\$s$/', $chunk, $match) === 1) {
                $argumentIndex = (int) $match[1];
            }

            if ($argumentIndex === null) {
                $parts[] = ['text' => $chunk, 'escaper' => null, 'literal' => false];

                continue;
            }

            $argument = $arguments[$argumentIndex]->value ?? null;
            $parts[] = [
                'text' => null,
                'escaper' => $argument instanceof Node\Expr\FuncCall ? AstHelper::functionName($argument) : null,
                'literal' => $argument instanceof Node\Expr && $this->wrapsSafeLiteral($argument),
            ];
        }

        return $parts;
    }

    /**
     * The first escaper that does not suit the context it was dropped into.
     *
     * @param list<array{text: ?string, escaper: ?string, literal: bool}> $parts
     *
     * @return array{0: string, 1: string, 2: string}|null
     */
    private function firstMismatch(array $parts): ?array
    {
        $text = '';

        foreach ($parts as $part) {
            if ($part['text'] !== null) {
                $text .= $part['text'];

                continue;
            }

            $escaper = $part['escaper'];

            // An unescaped hole, or a call this rule does not recognise as an
            // escaper at all. `wp_get_referer()` is a *source*, and reporting it
            // as the wrong escaper for its context both misnames the problem and
            // duplicates the ordinary output rule, which already has it.
            if ($escaper === null || ! $this->isEscaper($escaper)) {
                $text .= 'x';

                continue;
            }

            // A hardcoded literal argument — `esc_html__( 'Open Date Picker' )` —
            // is developer-authored text, not attacker input, and this rule
            // reports attacker-controlled breakouts. If the constant carries no
            // context-breaking character it cannot break out of anything.
            if ($part['literal']) {
                $text .= 'x';

                continue;
            }

            $problem = $this->mismatch($text, strtolower($escaper));

            if ($problem !== null) {
                return [$escaper, $problem[0], $problem[1]];
            }

            $text .= 'x';
        }

        return null;
    }

    /**
     * Is this a call whose job is escaping for output?
     *
     * Only these are judged. A function this rule has no opinion about is left
     * to the ordinary output rules rather than accused of being the wrong tool
     * for a job it was never doing.
     */
    private function isEscaper(string $name): bool
    {
        $name = strtolower($name);

        return in_array($name, self::HTML_ESCAPERS, true)
            || in_array($name, self::ATTR_ESCAPERS, true)
            || in_array($name, self::URL_ESCAPERS, true)
            || in_array($name, self::JS_ESCAPERS, true)
            || $name === 'esc_url_raw'
            || $name === 'esc_textarea';
    }

    /**
     * @return array{0: string, 1: string}|null what is needed, and where it landed
     */
    private function mismatch(string $before, string $escaper): ?array
    {
        // absint()/intval() yield an integer, which cannot carry a breakout in
        // any context — quoted or unquoted attribute, URL scheme, or script
        // body. Never a mismatch, wherever it lands.
        if (in_array($escaper, self::INTEGER_ESCAPERS, true)) {
            return null;
        }

        if (MarkupPosition::inScript($before)) {
            return in_array($escaper, self::JS_ESCAPERS, true)
                ? null
                : ['only JSON encoding or esc_js() neutralises a string breakout', 'inside a <script> block'];
        }

        $attribute = MarkupPosition::openAttribute($before);

        if ($attribute === null) {
            // HTML text, when the statement shows it: completed markup before
            // the hole, no tag left open. json_encode() leaves `<` intact, so
            // JSON printed into body text is live markup. The empty-context
            // case stays unjudged — a bare `echo wp_json_encode( $x )` may sit
            // inside a <script> block a previous statement opened, and this
            // rule only speaks for what the statement in front of it shows.
            if (
                in_array($escaper, self::JSON_ENCODERS, true)
                && str_contains($before, '>')
                && ! MarkupPosition::insideTag($before)
            ) {
                return [
                    'json_encode() leaves < intact — esc_html() around it, or a <script> block',
                    'in HTML text',
                ];
            }

            return null;
        }

        [$name, $quote, $valueSoFar] = $attribute;

        if ($quote === null) {
            // esc_url()'s character filter strips the space, `>` and quotes
            // that could end an unquoted value, so nothing in its output can
            // terminate the attribute. Every other escaper leaves the space.
            return in_array($escaper, [...self::URL_ESCAPERS, 'esc_url_raw'], true)
                ? null
                : ['an unquoted attribute can be escaped out of with a space', 'in an unquoted attribute'];
        }

        // A value that already carries a scheme-terminating character cannot
        // have its scheme chosen by the hole: `href="#…"` is a fragment and
        // `href="/…"` is a path wherever the rest of the value goes, so
        // attribute rules apply, not URL rules.
        if (in_array($name, self::URL_ATTRIBUTES, true) && preg_match('~[#/?:]~', $valueSoFar) !== 1) {
            if (in_array($escaper, self::URL_ESCAPERS, true)) {
                return null;
            }

            if ($escaper === 'esc_url_raw' && $quote === '"') {
                return null;
            }

            return $escaper === 'esc_url_raw'
                ? ['esc_url_raw() leaves an apostrophe intact', sprintf("in a single-quoted %s attribute", $name)]
                : ['only esc_url() rejects a javascript: scheme', sprintf('in a %s attribute', $name)];
        }

        if ($this->isEventHandler($name)) {
            if (in_array($escaper, self::JSON_ENCODERS, true)) {
                return [
                    "the JSON's own quotes end the attribute before any JavaScript runs — esc_attr() around it",
                    sprintf('in the %s handler', $name),
                ];
            }

            return in_array($escaper, self::JS_ESCAPERS, true)
                ? null
                : ['an event handler is JavaScript, not markup', sprintf('in the %s handler', $name)];
        }

        // esc_js() is in the attribute-safe set and the JSON pair is not: the
        // former entity-encodes quotes, the latter has to emit them.
        return in_array(
            $escaper,
            [...self::ATTR_ESCAPERS, ...self::URL_ESCAPERS, ...self::QUOTE_ENCODING_ESCAPERS, 'esc_js'],
            true,
        )
            ? null
            : ['esc_attr() is what protects an attribute', 'in a quoted attribute'];
    }

    private function isEventHandler(string $name): bool
    {
        return str_starts_with($name, 'on') && strlen($name) > 2;
    }

    /**
     * Does this escaper call wrap a constant string with nothing that could
     * break out of any output context?
     *
     * The argument to inspect is the first — `esc_html__( $text, $domain )` puts
     * the text first — so a literal there is developer-authored and cannot be
     * attacker input.
     */
    private function wrapsSafeLiteral(Node\Expr $call): bool
    {
        if (! $call instanceof Node\Expr\FuncCall) {
            return false;
        }

        $argument = $call->getArgs()[0]->value ?? null;

        return $argument instanceof Node\Expr && $this->isSafeLiteral($argument);
    }

    /**
     * A compile-time string constant that carries no character able to open a
     * new context: no angle bracket, quote, backslash, backtick or newline.
     */
    private function isSafeLiteral(Node\Expr $node): bool
    {
        if ($node instanceof Node\Scalar\String_) {
            return preg_match('/[<>"\'\\\\`\r\n]/', $node->value) !== 1;
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return $this->isSafeLiteral($node->left) && $this->isSafeLiteral($node->right);
        }

        return false;
    }
}
