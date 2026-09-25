# Design: a two-pass engine that does not hold every graph at once

**Status:** proposal, for review.
**Goal:** cut peak memory so that a scan with a large reference set fits in a
normal machine. Speed is secondary. Correctness is not negotiable: every finding,
trace and warning must be byte-identical to today's engine.

## Recommendation

Split the scan into two passes and stop holding every control flow graph for
the whole run.

- **Pass 1** reads each file, extracts what the rest of the scan needs about it
  as plain data, and drops the file's graph.
- **Pass 2** runs the interprocedural fixed point and the findings pass as it
  does today, but rebuilds a function's graph from source when it needs it, and
  keeps rebuilt graphs only up to a memory budget.

Pass 2 keeps today's body analysis unchanged. That is the whole reason to
prefer it: the analysis that decides findings does not change, so exactness
follows from the design rather than from a long parity effort. A second design,
symbolic summaries composed without any graph, is described below and not
recommended now. It would use a little less memory than the first design at a
small budget, and would be faster, but it means rewriting about 7,100 lines of
body analysis and matching it exactly.

## The problem, measured

Every file's graph is built during parsing and held until the scan ends. The
body analysis needs a function's graph each time the function is analysed, and
the fixed point analyses functions over several rounds, so today's design keeps
them all.

Measured on a client scan: 1,337 scanned files and 4 reference trees, 3,708
files in total.

| | Heap |
|---|---|
| Peak, after the recent changes | 2,451MB |
| Graphs, the bulk of that | about 2,300MB |
| Summary table, serialised | 19.8MB |
| Property taint map, serialised | 3.4MB |
| Scope table, serialised | 6.7MB |
| Read log, entries | 80,232 |

The state that must survive between rounds is small. Serialised, it is about
30MB. Even allowing for PHP's in-memory overhead, it is a small fraction of the
peak. Nearly all of the peak is graphs held in case a later round needs them.

Memory grows with the number of files:

| Configuration | Files | Peak |
|---|---|---|
| Client benchmark, 4 reference trees | 3,708 | 2.45GB, measured |
| Client scan, 17 reference trees | 19,011 | about 9GB, estimated from the benchmark |
| Client scan, 168 reference trees | 63,658 | about 30GB, estimated |

The last row is the case that motivated this. It does not fit in a 32GB
machine with anything else running.

### How much each round needs

The worklist changed what "needing a graph again" means. On the benchmark,
27,605 functions:

| Round | Functions analysed |
|---|---|
| 1 | 27,605, all of them |
| 2 | 14,892 |
| 3 | 2,273 |
| 4 | 231 |
| 5 | 50 |
| 6 | 6 |

That is about 1.6 analyses per function. After round 2, almost every graph
held in memory is never used again.

### What building a graph costs

Parsing and building a graph costs about 5ms per file on typical plugin code,
measured over the 24,798 corpus files, and 15 to 20ms on the largest files, such
as Gravity Forms'. Rebuilding every file once costs about as long as today's
parse phase: 50 seconds on the benchmark.

## What holds a graph today

A graph can only be dropped when nothing else points into it. These are the
structures that live across the scan, and what they store:

| Structure | Holds graph objects? |
|---|---|
| `UserFunctionTable` | **Yes.** Every `FunctionContext`, which holds the file and the `Func`, plus a map from `Func` back to context |
| `InterproceduralResolver` order, `Scanner` contexts | **Yes**, through the same contexts |
| `SummaryTable`, `PropertyTaintMap`, `ScopeTable` | No. Strings, taint sets and trace steps |
| `CallGraph`, `IncludeGraph`, `ConstantTable`, `DeclaredTypes`, `ClassHierarchy` | No. Strings |
| `HookGraph`, `RestRouteTable` | No. Call targets resolved with no arguments |

So only the function table keeps graphs alive, and it is the table everything
else asks for a function.

### What one function's analysis reads from other functions

This decides whether pass 2 can work one file at a time. Analysing a function
reads:

- **Its own graph.**
- **Other functions' metadata:** parameter names, by-reference and variadic
  flags, the class a method belongs to. `byReferencePositions()`,
  `describeReturn()` and the call resolver read these.
- **A closure's graph, when the closure is declared in the body being
  analysed.** `CallableResolver::closureBehind()` follows an operand to its
  declaration. That declaration is always in the same file, so the file the
  function came from is enough.
- **The shared tables above**, which are plain data.

No function reads another function's body. That is what makes the design
below possible.

## Design: rebuild graphs on demand, under a budget

### Pieces

- **Function metadata.** `UserFunctionTable` keeps a metadata record per
  function instead of a `FunctionContext`: its key, display name, file, class,
  and each parameter's name, by-reference flag, variadic flag and declared type.
  Everything that asks about another function today asks this record.
- **A body provider.** A new component hands out a `FunctionContext` for a key
  by loading the function's file: from its cache if the file is there,
  otherwise by rebuilding the graph from source with the same `CfgBuilder`.
  Closures resolve through the loaded file, by the same key
  `FunctionContext::keyFor()` computes today.
- **A cache with a memory budget.** Loaded files stay in memory until the
  budget is reached, then the least recently used file is dropped. The budget
  is set with a new option, for example `--memory-budget=4G`. With no budget
  set, nothing is ever dropped, which is today's behaviour.

### Pass 1: read every file once, keep data only

Pass 1 has to produce everything today's setup phase produces before
resolution starts: symbols, types, the class hierarchy, constants, hooks, the
call graph, include targets, REST routes, and structural-rule findings. Some of
those need the whole program's symbols before they can be built. For example,
call resolution needs every class's methods, and hook names need constants. So
pass 1 is two sweeps over the files:

1. **Symbols.** For each file: build the graph, record function metadata,
   declared types, the class hierarchy, and the constant definitions, then drop
   the graph. This is today's indexing step.
2. **Edges.** For each file: rebuild or reuse the graph, then run the existing
   builders for that file's functions: hooks, call graph, includes and REST
   routes. For scanned files, run the structural rules while the AST is still
   there. Then drop the graph and the AST.

Two things need care in the edges sweep:

- **The constant table is a fixed point over files.** A constant can be built
  from another file's function return. `ConstantTableBuilder::buildBoth()`
  already iterates. It needs to either keep its handful of `define()` operands
  per file, or repeat the sweep until the table stops changing.
- **Permission callbacks are read when the route's callback is entitled.** A
  permission callback can live in another file from its route. The body
  provider loads it on demand, like any other function.

Both sweeps drop each graph once the file is done, so memory during pass 1 is
the tables plus the cache.

### Pass 2: the same fixed point, with bodies on demand

`InterproceduralResolver` keeps its order, worklist and read log. The only
change is where a function's body comes from: the body provider, by key,
instead of a context held since parsing. The findings pass does the same for
scanned functions and for reference functions that call into scanned code.

The call order is callees first, and it does not group functions by file. So
with a small budget, a file can be rebuilt several times in one round. That
costs time, not correctness. Measuring how often it happens on real
configurations is part of the plan below, and a file-aware order inside each
strongly connected component is one way to reduce it.

### Workers

`--jobs` forks after pass 1. Each worker gets its own cache. The budget applies
per scan, so it's divided between the workers, and each rebuilds what it needs
from source.

### Why this is exact

The body analysis runs the same code on a graph built from the same source by
the same builder. The graph objects are new, but the analysis never compares
graph objects across rounds. The places that could matter:

- **Keys.** Function keys, including `{anonymous}#N` closure names, come from
  php-cfg's per-file numbering, which is deterministic for the same file.
- **Object identity.** Per-analysis structures such as `ClassTypeMap`,
  `TaintState` and the finding de-duplication key use object identity only
  within one analysis. They never carry identity across rounds.
- **Shared tables.** These store strings and trace steps only.
- **The read log.** It records string keys, so the worklist is unaffected.

The design still needs proof, and the plan gets it the same way the worklist
did: a comparison tool, and a test that forces a rebuild of every function.

## Expected memory

Resident memory becomes metadata, plus the shared tables, plus the cache.

| Configuration | Today | With a 1GB budget | With no budget |
|---|---|---|---|
| Client benchmark | 2.45GB | about 1.2GB | 2.45GB, unchanged |
| 168 reference trees | about 30GB | about 2 to 3GB | about 30GB |

These are estimates. The tables for the 168-tree configuration are projected
from the benchmark by function count, about 17 times as many. Pass 1 of the
prototype has to measure them, because they set the floor.

## Expected time

- **Pass 1:** two sweeps instead of one parse, so about one extra parse phase.
  That is 50 seconds on the benchmark, when the budget is too small to keep the
  graphs from the first sweep to the second.
- **Pass 2:** rebuilds only what the budget has dropped. With round 2
  analysing about half the functions, a small budget costs at most one more
  parse phase. Later rounds cost little.
- **Findings pass:** rebuilds the scanned files, which are usually a small part
  of the total.

On the benchmark, a small budget should cost roughly 1.5 to 2 times today's run
time. With enough budget to hold everything, the time is unchanged.

## Alternative: symbolic summaries, no graphs in pass 2

This is the design the review described: pass 1 produces a symbolic local
summary per function, and pass 2 composes summaries without ever building a
graph again.

A summary would have to record, per function:

- **Flows** from each input to each output. Inputs are parameters, sources,
  properties, globals and the results of calls. Outputs are the return value,
  by-reference parameters, properties, globals and captures. Each flow records
  what it clears and what it adds.
- **Sinks**, each with the conditions the body analysis applies there today:
  - the guards that dominate the sink
  - the markup context and quote character at an echo
  - the capability checks that entitle the caller
  - the query shape at a database call
- **Unresolved call sites**, with how each argument maps onto the call.

Composition is where the difficulty lies. Several things the engine does
today are not a simple union of flows:

- **Escape markers.** The escaped and escape-voided markers depend on order,
  and on which alternative carried both.
- **Per-key array taint** at call boundaries.
- **Literal anchoring and query-shape checks.** Both look through a value's
  construction.
- **Unknown-provenance seeding.** It depends on whether a function has callers.

Each of those would need a symbolic form and a composition rule, and all of it
would have to match today's findings exactly.

| | Rebuild on demand | Symbolic summaries |
|---|---|---|
| Peak memory at a small budget | tables, metadata and cache | tables and metadata |
| Time | slower as the budget shrinks | likely faster than today |
| Changes to the body analysis | none | a rewrite of about 7,100 lines |
| How exactness is shown | by construction, checked by a comparison tool | by matching every fixture, the corpus and the CVE set, one behaviour at a time |
| Risk | low | high |

Rebuild on demand reaches the memory goal on its own. Symbolic summaries would
make sense later only if the time cost of a small budget turns out to be too
high in practice. They can be built on top of the first design, one function
shape at a time.

## Plan

Each step lands on its own, keeps findings byte-identical, and is checked
before the next begins.

1. **Metadata and a body provider, nothing dropped.** Move the function
   table to metadata records and route every body access through the
   provider, with no budget. Nothing changes except the code paths.
   - **Gate:** full suite, corpus, CVE, fixture and suite baselines unchanged.
2. **A forced-rebuild mode for tests.** A budget of zero rebuilds every
   function from source every time it's needed. Run the whole suite in that
   mode, and add `tools/compare-budget.php`, modelled on
   `tools/compare-incremental.php`, to compare a zero budget with no budget
   finding by finding.
   - **Gate:** identical on all 50 corpus plugins and the client benchmark.
3. **Stream pass 1.** Split setup into the two sweeps. Drop each file's graph
   and AST when its sweep is done.
   - **Gate:** identical, and pass 1's peak measured with `--debug-memory`.
4. **Budgeted pass 2.** Enable eviction in the resolver and the findings pass.
   Add `--memory-budget` and a memory line to `--debug-memory` showing cache
   hits, misses and rebuilds.
   - **Gate:** identical at several budgets. Record memory and time for the
     benchmark, and for the 17-tree and 168-tree client configurations.
5. **Choose a default.** Decide from the measurements whether the default is
   unlimited, a fixed size, or a fraction of `memory_limit`. Update the
   troubleshooting guide.

## Open questions

- **The constant table.** Keep the `define()` operands, or repeat the sweep?
  The first uses a little memory and the second takes time. The measurement in
  step 3 decides.
- **Cache policy.** Least recently used, or aware of the call order? LRU is
  simple. An order-aware policy could avoid rebuilding a file several times in
  one round. Measure LRU first.
- **The table floor.** How large are the shared tables on the 168-tree
  configuration? If they approach the budget, the summaries' trace steps are
  the first thing to make smaller.
- **Default budget.** Unlimited keeps today's speed for small scans. A default
  tied to `memory_limit` would make large scans fit without anyone choosing a
  number.
