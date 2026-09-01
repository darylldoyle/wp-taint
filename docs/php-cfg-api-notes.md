# `ircmaxell/php-cfg` API notes

Written against **v0.8.1** (installed 2026-08-27). Every symbol below was verified
by reading `vendor/ircmaxell/php-cfg/lib/PHPCfg/` and by running probe scripts
against real PHP input. Do not trust the implementation plan's guessed names,
trust this file, and re-verify it if the dependency is ever bumped.

The plan predicted a `^0.2` constraint pulling `nikic/php-parser` v4. That is
wrong for the current release: **v0.8.1 requires `nikic/php-parser ^5.0` and
PHP >= 7.4**. The kill gate the plan set on this does not trip.

## Entry point

```php
$astParser = (new PhpParser\ParserFactory())->createForNewestSupportedVersion();
$parser    = new PHPCfg\Parser($astParser);          // optional 2nd arg: PhpParser\NodeTraverser
$script    = $parser->parse($sourceCode, $fileName); // PHPCfg\Script
```

`Parser::__construct` installs three AST visitors of its own (`NameResolver`,
`LoopResolver`, `MagicStringResolver`). If you pass your own `NodeTraverser`,
those are appended to it, so pass a traverser only when you want your visitors
to run *before* php-cfg's name resolution.

`Parser::parse()` throws `PhpParser\Error` on a syntax error. It never returns a
partial script. `CfgBuilder` converts that into a `ParseResult` failure.

To capture the raw nikic AST alongside the CFG (structural rules need it), parse
the AST yourself and call `Parser::parseAst($ast, $fileName)`. **Caveat:**
`parseAst()` mutates the AST in place through its own traverser, so the AST you
keep is the *name-resolved* one. That is what we want.

## Script / Func / Block / Op

| Symbol | Shape |
| --- | --- |
| `Script::$main` | `Func` for top-level code, named `{main}` |
| `Script::$functions` | `list<Func>`, every function, method, closure and arrow function in the file, flat, integer-keyed |
| `Func::$name` | short name for methods (`bar`), fully-qualified for functions (`My\Space\helper`), `{anonymous}#N` for closures |
| `Func::$class` | `Operand\Literal` holding the FQCN, or `null` |
| `Func::getScopedName()` | `Class::method` or the function name |
| `Func::$flags` | bitmask, `Func::FLAG_*` (`FLAG_CLOSURE = 0x80`) |
| `Func::$params` | `list<Op\Expr\Param>` |
| `Func::$cfg` | entry `Block`, or `null` for abstract/interface methods |
| `Func::$callableOp` | the declaring `Op\Stmt\Function_` / `Op\Stmt\ClassMethod` / `Op\Expr\Closure` |
| `Block::$children` | `list<Op>` in execution order |
| `Block::$parents` | `list<Block>` predecessors |
| `Block::$phi` | `list<Op\Phi>`, **phi nodes live on the block, not in `children`** |
| `Block::$dead` | bool |

### `Func` carries no source position

`Func` extends `Op` but the parser never gives it attributes: `getLine()` returns
`-1` and `getFile()` returns `'unknown'`. Use `Func::$callableOp` for position.
`{main}` has no `callableOp`; fall back to the file being scanned.

## Def-use: the two properties the whole engine rests on

```php
abstract class Operand {
    public array $ops    = [];  // Ops that WRITE this operand
    public array $usages = [];  // Ops that READ this operand
}
```

`Operand::$ops` is the def side, `Operand::$usages` is the use side. Both are
maintained by `Op::addWriteRef()` / `Op::addReadRef()` in every op constructor,
so they are populated as a side effect of parsing. Propagation is a worklist over
`$usages`.

`Op::isWriteVariable(string $propertyName)` reports whether a named property of an
op is a write target, `Assign` returns true for `var` and `result`, most exprs
only for `result`.

`Op::getVariableNames()` returns the property names holding operands, so an op's
operands can be enumerated generically. Some named properties are arrays
(`args`, `list`, `values`, `vars`), some are nullable (`dim`, `expr` on
`Return_`). Enumerate defensively.

## Operand classes

After parsing, **almost every operand you meet is an `Operand\Temporary`.**

| Class | Meaning |
| --- | --- |
| `Operand\Temporary` | An SSA value. `$original` is the `Operand\Variable` it was renamed from, or `null` for a pure intermediate |
| `Operand\Variable` | `$name` is an `Operand`, a `Literal` for normal variables, something else for variable-variables |
| `Operand\Literal` | `$value` is the PHP scalar |
| `Operand\BoundVariable` | extends `Variable`; `global`/`static`/closure `use` bindings. `$byRef`, `$scope` (`SCOPE_*`) |
| `Operand\NullOperand` | placeholder |

So the idiom for "what is this variable called" is:

```php
$op->var instanceof Operand\Temporary
    && $op->var->original instanceof Operand\Variable
    && $op->var->original->name instanceof Operand\Literal
    ? $op->var->original->name->value
    : null
```

Superglobals appear as one shared `Temporary` per file whose `original` is a
`Variable` named `_GET` (no leading `$`), with `ops === []` (never written) and
`usages` listing every read. That single object is the taint seed.

## SSA renaming and phi nodes

Each assignment produces a **new** `Temporary` for the same source variable, so
`$a` written three times yields three distinct operands. Merge points get a
`Op\Phi` on the *successor* block:

```
Block#4
    Var#12<$a> = Phi(Var#7<$a>, Var#10<$a>)
```

`Op\Phi::$vars` are the incoming operands, `Op\Phi::$result` the merged one. Phi
nodes are **not** in `Block::$children`; iterate `Block::$phi` separately or they
are silently skipped, which would be a silent false negative on every `if/else`.

`Traverser` does not visit phi nodes at all. Our own block walk must.

## Ops that matter for taint

| Op | Operands | Notes |
| --- | --- | --- |
| `Op\Expr\Assign` | `var` (write), `expr` (read), `result` | `result` is the expression value of the assignment |
| `Op\Expr\AssignRef` | same | reference aliasing; we over-approximate |
| `Op\Expr\BinaryOp\Concat` | `left`, `right`, `result` | binary `.` |
| `Op\Expr\ConcatList` | `list` (array), `result` | **string interpolation and heredocs**, not just `.` chains |
| `Op\Expr\FuncCall` | `name`, `args` (array), `result` | `name` is a `Literal` for a static name, a `Temporary` for `$fn()` |
| `Op\Expr\NsFuncCall` | `name`, `nsName`, `args`, `result` | namespaced call with a global fallback; check both names |
| `Op\Expr\MethodCall` | `var`, `name`, `args`, `result` | |
| `Op\Expr\StaticCall` | `class`, `name`, `args`, `result` | `class` is a `Literal` when resolvable |
| `Op\Expr\New_` | `class`, `args`, `result` | |
| `Op\Expr\ArrayDimFetch` | `var`, `dim` (nullable), `result` | `$_GET['x']`; `dim` is a `Literal` for a constant key |
| `Op\Expr\Array_` | `keys`, `values`, `byRef`, `result` | array literal |
| `Op\Expr\PropertyFetch` | `var`, `name`, `result` | |
| `Op\Expr\Cast\Int_` etc. | `expr`, `result` | int/float/bool casts sanitise everything |
| `Op\Expr\Include_` | `expr`, `type`, `result` | `type` is `TYPE_INCLUDE`/`_ONCE`/`TYPE_REQUIRE`/`_ONCE` |
| `Op\Expr\Eval_` | `expr`, `result` | |
| `Op\Expr\Print_` | `expr`, `result` | |
| `Op\Expr\Closure` | `func`, `useVars`, `result` | implements `CallableOp` |
| `Op\Terminal\Echo_` | `expr` | |
| `Op\Terminal\Return_` | `expr` (**nullable**) | |
| `Op\Terminal\Throw_` | `expr` | |
| `Op\Terminal\GlobalVar` | `var` | `global $wpdb;` |
| `Op\Phi` | `vars`, `result` | on `Block::$phi` |
| `Op\Stmt\JumpIf` | `cond`, `if`, `else` | sub-blocks |
| `Op\Stmt\Jump` | `target` | sub-block |

Interpolation lowering is worth restating because it is easy to get wrong:
`"hello $a world"` and a heredoc both become `Op\Expr\ConcatList`, **not** a chain
of `Concat`. A propagation loop that only handles `Concat` misses every
interpolated XSS, which is the most common shape in WordPress code.

## Source positions

Ops carry nikic attributes: `filename`, `startLine`, `endLine`, `startFilePos`,
`endFilePos`, `startTokenPos`, `endTokenPos`.

```php
$op->getLine();                       // startLine, or -1
$op->getFile();                       // filename, or 'unknown'
$op->getAttribute('startFilePos');    // byte offset, or the default you pass
```

Columns are **not** provided, derive them from `startFilePos` against the file
source. Synthetic ops (the implicit `Terminal_Return` closing every function)
have **no attributes at all**: `getLine()` is `-1` and `startFilePos` is absent.
Always guard, and omit the caret line rather than guessing a column.

`Op::getAttribute()` returns by reference with a by-reference default, so
`getAttribute('startFilePos', -1)` on a literal default emits a notice under some
configurations. Assign the default to a variable first, or use `hasAttribute()`.

## Traverser and visitors

```php
$traverser = new PHPCfg\Traverser();
$traverser->addVisitor(new PHPCfg\Visitor\Simplifier());
$traverser->traverse($script);
```

`Visitor` events: `enterScript`, `leaveScript`, `enterFunc`, `leaveFunc`,
`enterBlock`, `enterOp`, `leaveOp`, `leaveBlock`, `skipBlock`. Extend
`AbstractVisitor` for no-op defaults. Returning `Visitor::REMOVE_OP` /
`REMOVE_BLOCK` from `leaveOp` / `leaveBlock` mutates the graph.

**The traverser dispatches the first non-null return from any visitor and stops.**
Visitors that return values interfere with each other; ours return `null`.

### `Visitor\Simplifier`

Collapses blocks whose only child is a `Jump`, and removes trivial phi nodes
(single-operand, or self-referential). Run it once, before analysis. It shrinks
the graph substantially and removes phi noise that would otherwise widen taint
sets for no reason.

### `Visitor\DeclarationFinder`

Collects `getClasses()`, `getInterfaces()`, `getTraits()`, `getMethods()`,
`getFunctions()`, `getConstants()`. Returns the declaring **ops**, not `Func`s.
`Script::$functions` is usually the more direct route for our purposes.

### `Visitor\CallFinder`

`getFuncCalls()`, `getNsFuncCalls()`, `getMethodCalls()`, `getStaticCalls()`,
`getNewCalls()`. Note the return shape is **`list<array{0: Op, 1: Func}>`**, a
tuple of call op and enclosing function, despite the docblocks claiming
`Op\Expr\FuncCall[]`. The docblocks are wrong; the code is right.

### `Printer\Text` and `Printer\GraphViz`

`(new Printer\Text())->printScript($script)` gives the SSA dump used by
`wp-taint dump-cfg`. `Printer\GraphViz` needs `phpdocumentor/graphviz`, which
php-cfg requires, and emits dot source via `printScript()`.

## Things that bit us

1. **`Block::$phi` is separate from `Block::$children`.** Missing it silently
   loses all branch merges.
2. **`ConcatList` vs `Concat`.** Interpolation is `ConcatList`.
3. **`Func` has no line number.** Use `Func::$callableOp`.
4. **`CallFinder` returns tuples**, not ops.
5. **`Operand::$ops` is writers, `$usages` is readers.** The names read backwards
   the first time.
6. **`use PhpCfg\Operand;`**, several op files import the namespace with the
   wrong case (`PhpCfg` vs `PHPCfg`). It works because PHP namespaces are
   case-insensitive, but static analysers may flag it. It is upstream's bug, not
   ours.
7. **`PHPTypes\Type`** is referenced by `Operand::$type` but `ircmaxell/php-types`
   is not a hard dependency and is not installed. Never touch `Operand::$type`;
   PHPStan is told to ignore the unresolvable class.

## Lowering shapes confirmed by probe

Verified against real input, because guessing any of these wrong is a silent
false negative.

| Source | Lowered to |
| --- | --- |
| `"a $b c"`, heredoc | `Op\Expr\ConcatList` |
| `'a' . $b` | `Op\Expr\BinaryOp\Concat` |
| `$a ?? $b` | `Op\Expr\BinaryOp\Coalesce`, a `BinaryOp`, so both sides propagate |
| `` `cmd $x` `` | a **`shell_exec()` `FuncCall`**, not a distinct backtick op |
| `(int) $x` | `Op\Expr\Cast\Int_` |
| `foreach ($a as $k => $v)` | `Iterator\Reset`, `Iterator\Valid`, `Iterator\Key`, `Iterator\Value`, each reading the same iterable operand |
| `$arr['k'] = $v` | `ArrayDimFetch($arr, 'k') → tmp`, then `Assign(var: tmp, expr: $v)` |
| `$obj->p = $v` | `PropertyFetch($obj, 'p') → tmp`, then `Assign(var: tmp, expr: $v)` |

The last two matter more than they look. **The assignment target is the fetch
result temporary, not the base operand**, and a later read of the same element
produces a *different* temporary with no SSA link to the write. Element and
property taint therefore have to be modelled explicitly:

- Array writes propagate to the **base** operand, the whole array is tainted,
  which is the over-approximation recorded in `KNOWN_LIMITATIONS.md`. This works
  because the base operand (`Var#19<$arr>`) is shared between the writing fetch
  and every later reading fetch.
- Property writes propagate into a `class::property` map that outlives the
  function, because `$this->x = $tainted` in one method and `echo $this->x` in
  another is a single dataflow across two function bodies.
