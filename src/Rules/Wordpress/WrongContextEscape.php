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
     * `esc_url_raw` is deliberately absent from the URL set: it is for storage
     * and redirects, not for output, and using it in markup is its own mistake.
     */
    private const HTML_ESCAPERS = ['esc_html', 'esc_html__', 'esc_html_e', 'esc_html_x', 'wp_kses', 'wp_kses_post'];

    private const ATTR_ESCAPERS = [
        'esc_attr', 'esc_attr__', 'esc_attr_e', 'esc_attr_x',
        'sanitize_html_class', 'sanitize_key', 'sanitize_title', 'absint', 'intval',
    ];

    private const URL_ESCAPERS = ['esc_url'];

    private const JS_ESCAPERS = ['esc_js', 'wp_json_encode', 'json_encode'];

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
                    '%s() escapes for HTML text, and this value lands %s, where %s. An escaper is present, so '
                        . 'a check that only asks whether one was called reports nothing here.',
                    $escaper,
                    $where,
                    $wanted,
                ),
                $escaper,
            );
        }

        return $findings;
    }

    /**
     * Output statements, decomposed into literal text and escaper calls in order.
     *
     * @return list<array{0: Node, 1: list<array{text: ?string, escaper: ?string}>}>
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
     * A concatenation, flattened left to right into text and escaper calls.
     *
     * @return list<array{text: ?string, escaper: ?string}>
     */
    private function flatten(Node\Expr $expr): array
    {
        if ($expr instanceof Node\Expr\BinaryOp\Concat) {
            return [...$this->flatten($expr->left), ...$this->flatten($expr->right)];
        }

        if ($expr instanceof Node\Scalar\String_) {
            return [['text' => $expr->value, 'escaper' => null]];
        }

        if ($expr instanceof Node\Scalar\InterpolatedString) {
            $parts = [];

            foreach ($expr->parts as $part) {
                $parts = [...$parts, ...(
                    $part instanceof Node\InterpolatedStringPart
                        ? [['text' => $part->value, 'escaper' => null]]
                        : $this->flatten($part)
                )];
            }

            return $parts;
        }

        $escaper = $expr instanceof Node\Expr\FuncCall ? AstHelper::functionName($expr) : null;

        return [['text' => null, 'escaper' => $escaper]];
    }

    /**
     * `printf( '<a href="%s">', esc_attr( $url ) )`: the format supplies the
     * context and the arguments supply the escapers.
     *
     * Only `%s` is mapped, positionally. A numeric or padded specifier cannot
     * carry a breakout, and `%1$s`-style ordering is left alone rather than
     * guessed at.
     *
     * @return list<array{text: ?string, escaper: ?string}>
     */
    private function fromFormat(Node\Expr\FuncCall $call): array
    {
        $arguments = $call->getArgs();
        $format = ($arguments[0]->value ?? null);

        if (! $format instanceof Node\Scalar\String_) {
            return [];
        }

        if (str_contains($format->value, '%1$') || str_contains($format->value, '%2$')) {
            return [];
        }

        $parts = [];
        $index = 1;

        $chunks = preg_split('/(%s)/', $format->value, -1, PREG_SPLIT_DELIM_CAPTURE);

        foreach ($chunks === false ? [] : $chunks as $chunk) {
            if ($chunk !== '%s') {
                $parts[] = ['text' => $chunk, 'escaper' => null];

                continue;
            }

            $argument = $arguments[$index]->value ?? null;
            $index++;
            $parts[] = [
                'text' => null,
                'escaper' => $argument instanceof Node\Expr\FuncCall ? AstHelper::functionName($argument) : null,
            ];
        }

        return $parts;
    }

    /**
     * The first escaper that does not suit the context it was dropped into.
     *
     * @param list<array{text: ?string, escaper: ?string}> $parts
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
        if ($this->inScript($before)) {
            return in_array($escaper, self::JS_ESCAPERS, true)
                ? null
                : ['only JSON encoding or esc_js() neutralises a string breakout', 'inside a <script> block'];
        }

        $attribute = $this->openAttribute($before);

        if ($attribute === null) {
            return null;
        }

        [$name, $quoted] = $attribute;

        if (! $quoted) {
            return ['an unquoted attribute can be escaped out of with a space', 'in an unquoted attribute'];
        }

        if (in_array($name, self::URL_ATTRIBUTES, true)) {
            return in_array($escaper, self::URL_ESCAPERS, true)
                ? null
                : ['only esc_url() rejects a javascript: scheme', sprintf('in a %s attribute', $name)];
        }

        if ($this->isEventHandler($name)) {
            return in_array($escaper, self::JS_ESCAPERS, true)
                ? null
                : ['an event handler is JavaScript, not markup', sprintf('in the %s handler', $name)];
        }

        return in_array($escaper, [...self::ATTR_ESCAPERS, ...self::URL_ESCAPERS, ...self::JS_ESCAPERS], true)
            ? null
            : ['esc_attr() is what protects an attribute', 'in a quoted attribute'];
    }

    /**
     * Are we inside a `<script>` element, counting only complete tags?
     */
    private function inScript(string $before): bool
    {
        $opens = preg_match_all('/<script\b/i', $before);
        $closes = preg_match_all('#</script\s*>#i', $before);

        return $opens > $closes;
    }

    /**
     * The attribute the next value lands in, and whether it is quoted.
     *
     * A forward scan rather than a regex on the tail, because a value often
     * lands part-way through an attribute rather than immediately after the
     * quote:
     *
     *     <button onclick='doThing("   <- still inside onclick
     *
     * Matching `name="` at the end of the text answers no there, and that is
     * the case the rule most wants: JavaScript inside an event handler.
     *
     * @return array{0: string, 1: bool}|null
     */
    private function openAttribute(string $before): ?array
    {
        $inTag = false;
        $name = '';
        $collecting = false;
        $attribute = null;
        $quote = null;
        $openName = null;
        $length = strlen($before);

        for ($index = 0; $index < $length; $index++) {
            $character = $before[$index];

            if ($quote !== null) {
                if ($character === $quote) {
                    $quote = null;
                    $attribute = null;
                }

                continue;
            }

            if (! $inTag) {
                if ($character === '<') {
                    $inTag = true;
                    $name = '';
                    $collecting = true;
                    $attribute = null;
                }

                continue;
            }

            if ($character === '>') {
                $inTag = false;
                $attribute = null;

                continue;
            }

            if ($character === '=') {
                $attribute = strtolower($name);
                $name = '';
                $collecting = false;

                continue;
            }

            if ($character === '"' || $character === "'") {
                if ($attribute !== null) {
                    $quote = $character;
                    $openName = $attribute;
                }

                continue;
            }

            if (ctype_space($character)) {
                // Whitespace ends an unquoted value, and starts the next name.
                $attribute = null;
                $name = '';
                $collecting = true;

                continue;
            }

            if ($collecting) {
                $name .= $character;
            }
        }

        // The quote is still open, so the value lands inside it — whatever else
        // is in there. `onclick='doThing("` is still the onclick attribute, and
        // re-deriving the name with a regex over the tail loses exactly that
        // case, because the tail contains the other quote character.
        if ($quote !== null && $openName !== null) {
            return [$openName, true];
        }

        return $inTag && $attribute !== null ? [$attribute, false] : null;
    }

    private function isEventHandler(string $name): bool
    {
        return str_starts_with($name, 'on') && strlen($name) > 2;
    }
}
