<?php

declare(strict_types=1);

namespace Enshrined\WpTaint\Cfg;

use Enshrined\WpTaint\Support\PathHelper;
use PHPCfg\Parser as CfgParser;
use PHPCfg\Traverser;
use PHPCfg\Visitor\Simplifier;
use PhpParser\Error as PhpParserError;
use PhpParser\NodeTraverser;
use PhpParser\Parser as AstParser;
use PhpParser\ParserFactory;
use Throwable;

/**
 * The single point of contact with `ircmaxell/php-cfg`.
 *
 * The library is MIT but thinly maintained, so every use of it lives behind
 * this class. Replacing or forking it should touch this file and nothing else.
 * The API it actually exposes — as opposed to the API its docblocks claim — is
 * written down in `docs/php-cfg-api-notes.md`.
 */
final class CfgBuilder
{
    private readonly AstParser $astParser;

    public function __construct(private readonly string $projectRoot)
    {
        $this->astParser = (new ParserFactory())->createForNewestSupportedVersion();
    }

    public function buildFromFile(string $path): ParseResult
    {
        // Check readability rather than suppressing the warning: a suppressed
        // diagnostic is still a diagnostic, and the point of this class is that
        // nothing about a file is ever handled quietly.
        $source = is_file($path) && is_readable($path) ? file_get_contents($path) : false;

        if ($source === false) {
            return ParseResult::failure(new ParseError(
                PathHelper::relative($path, $this->projectRoot),
                0,
                'Unable to read file.',
            ));
        }

        return $this->build($source, $path);
    }

    public function build(string $source, string $path): ParseResult
    {
        $relative = PathHelper::relative($path, $this->projectRoot);

        try {
            $ast = $this->astParser->parse($source);
        } catch (PhpParserError $error) {
            return ParseResult::failure(new ParseError(
                $relative,
                $error->getStartLine() > 0 ? $error->getStartLine() : 0,
                $error->getRawMessage(),
            ));
        }

        if ($ast === null) {
            return ParseResult::failure(new ParseError($relative, 0, 'Parser returned no statements.'));
        }

        try {
            // Lower the constructs php-cfg cannot parse, before it sees them.
            // This runs ahead of php-cfg's own NameResolver, so the rewritten
            // nodes still get their names resolved normally.
            $compatibility = new CompatibilityVisitor();
            $traverser = new NodeTraverser();
            $traverser->addVisitor($compatibility);
            $ast = $traverser->traverse($ast);

            // A fresh PHPCfg\Parser per file: it keeps per-script state
            // (current class, current namespace, anonymous-class counter) in
            // instance properties and only resets some of it between calls.
            $cfgParser = new CfgParser($this->astParser);
            $script = $cfgParser->parseAst($ast, $path);

            $cfgTraverser = new Traverser();
            $cfgTraverser->addVisitor(new Simplifier());
            $cfgTraverser->traverse($script);
        } catch (PhpParserError $error) {
            return ParseResult::failure(new ParseError(
                $relative,
                $error->getStartLine() > 0 ? $error->getStartLine() : 0,
                $error->getRawMessage(),
            ));
        } catch (Throwable $error) {
            // php-cfg throws Error, RuntimeException and LogicException on
            // constructs it cannot lower, with no common base of its own.
            // Catching Throwable is deliberate: surfacing any failure as a
            // parse error keeps the "never silently skip a file" guarantee.
            // These land in --parse-report and set exit code 2, exactly like a
            // syntax error, so nothing disappears quietly.
            return ParseResult::failure(new ParseError(
                $relative,
                0,
                sprintf('%s: %s', self::shortClassName($error), $error->getMessage()),
            ));
        }

        return ParseResult::success(new ParsedFile(
            $path,
            $relative,
            $script,
            array_values($ast),
            new SourceMap($source),
            $compatibility->lowered(),
        ));
    }

    private static function shortClassName(Throwable $throwable): string
    {
        $parts = explode('\\', $throwable::class);
        $short = end($parts);

        return $short === false || $short === '' ? $throwable::class : $short;
    }
}
