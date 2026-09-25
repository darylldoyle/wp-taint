# Design: a two-pass engine that does not hold every graph at once

**Status:** proposal, for review.
**Goal:** cut peak memory so that a scan with a large reference set fits in a
normal machine. Speed is secondary. Correctness is not negotiable: every finding,
trace and warning must be byte-identical to today's engine.

## Recommendation

Split the scan into two passes and stop holding every control flow graph for
the whole run.

- **Pass 1** reads the files, extracts what the rest of the scan needs about
  them as plain data, and drops each file's graph.
- **Pass 2** runs the interprocedural fixed point and the findings pass as it
  does today, but rebuilds a function's graph from source when it needs it, and
  keeps rebuilt graphs only up to a memory budget.

The budget defaults to 4GB of graph cache. A scan whose graphs fit runs as fast
as today. The 17-tree client configuration drops from 7.97GB to about 5.5GB,
and the 168-tree one from about 26GB to about 9GB. The cost is time: about 2.1
times the run time on 17 trees, from rebuilding graphs the cache could not keep.

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
| Client scan, 17 reference trees | 19,008 | 7.97GB, measured |
| Client scan, 168 reference trees | 63,651 | about 26GB, projected |

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
measured over the 24,798 corpus files. Large reference files cost much more:
about 23ms each on average across the 17-tree configuration's reference trees.
Rebuilding every file once costs about as long as today's parse phase: 50
seconds on the benchmark, about 420 seconds on the 17-tree configuration.

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
- **A graph cache with a memory budget.** Loaded files stay in memory while
  the cache is under its budget. Once it is full, it admits no new files: a file
  it does not hold is rebuilt, used and dropped. The simulation below shows
  that this beats least recently used by about half, because the scan's access
  pattern is repeated sweeps. The budget caps the cache only; the floor is
  reported separately by `--debug-memory`. It is set with `--memory-budget`, and
  defaults to 4GB. `--memory-budget=0` rebuilds every time, for tests, and
  `--memory-budget=unlimited` never drops anything, which is today's
  behaviour.

### Pass 1: read the files, keep data only

Pass 1 has to produce everything today's setup phase produces before
resolution starts: symbols, types, the class hierarchy, constants, hooks, the
call graph, include targets, REST routes, and structural-rule findings. Some of
those need the whole program's symbols before they can be built. For example,
call resolution needs every class's methods, and hook names need constants. So
pass 1 is three sweeps over the files:

1. **Symbols.** For each file: build the graph, record function metadata,
   declared types, the class hierarchy, and the first constant pass, then drop
   the graph. This is today's indexing step.
2. **Constants.** The second constant pass, reading the first pass's table.
3. **Edges.** For each file: rebuild or reuse the graph, then run the existing
   builders for that file's functions: hooks, call graph, includes and REST
   routes. For scanned files, run the structural rules while the AST is still
   there. Then drop the graph and the AST.

Two things need care in the edges sweep:

- **The constant table needs two passes over every function.**
  `ConstantTableBuilder::buildBoth()` runs exactly two, each building a fresh
  table from the previous one's answers, because a constant is often defined
  from another constant or from a function's return. Edges need the final
  table, since hook names and include paths are built from constants. So pass 1
  is three sweeps: symbols and the first constant pass, the second constant
  pass, then edges. That reproduces today's result exactly. Keeping the
  `define()` and `return` operands between sweeps instead would not save much:
  an operand points at the ops that use it, so it would keep most of each
  function's graph alive.
- **Permission callbacks are read when the route's callback is entitled.** A
  permission callback can live in another file from its route. The body
  provider loads it on demand, like any other function.

Every sweep drops each graph once the file is done, unless the cache keeps it,
so memory during pass 1 is the tables plus the cache.

### Pass 2: the same fixed point, with bodies on demand

`InterproceduralResolver` keeps its order, worklist and read log. The only
change is where a function's body comes from: the body provider, by key,
instead of a context held since parsing. The findings pass does the same for
scanned functions and for reference functions that call into scanned code.

Each round is grouped by file. Files are ordered callees first by the
file-level call graph, and each file's functions keep their callees-first order
inside it, so a round builds each file at most once. The result is the same
fixed point, because the transfer functions are monotone and the fixed point
does not depend on the order. The order can change how many rounds it takes,
and the comparison tool checks both the result and the round count.

One thing does depend on the order: the trace kept for a stored value. A
property or an option written in several places keeps the trace with the
smallest signature among every trace offered for it, and some are offered
before the analysis settles. Measured when step 4 landed, the new order changed
5 traces in 2 of the 42 corpus plugins with findings, and nothing else. On
`main`, `--jobs=4` against `--jobs=1` already changed 10 traces in 4 plugins,
including those 2. So the order exposes an existing quirk rather than adding
one. KNOWN_LIMITATIONS.md records it. A budget never changes the order, so a
budgeted scan and an unbudgeted one still match byte for byte.

### Workers

`--jobs` forks after pass 1. Each worker gets its own cache. The budget applies
per scan, so it's divided between the workers, and each rebuilds what it needs
from source. The parent holds its equal part too. A worker starts with a copy
of the parent's cache and its count, so once that part is full the worker only
rebuilds.

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

Resident memory becomes a floor, which is the function metadata and the shared
tables, plus the graph cache, which the budget caps.

The floor was measured on the 17-tree client configuration: 19,008 files and
130,761 functions. The indexes and metadata held before resolution take about
0.3GB. The shared tables take about 1.2GB in memory, which is about 8.5 times
their serialised size of 130MB. The floor for the 168-tree configuration is
projected by function count, at 438,073 functions, 3.35 times as many.

| Configuration | Graphs | Floor | Today's peak | With a 4GB budget |
|---|---|---|---|---|
| Client benchmark | 2.3GB | about 0.2GB | 2.45GB | 2.45GB, everything fits |
| 17 reference trees | 6.2GB | about 1.5GB | 7.97GB, measured | about 5.5GB |
| 168 reference trees | about 20.7GB | about 5GB | about 26GB | about 9GB |

The floor matters once the graphs stop dominating. On the largest
configuration it is bigger than the budget itself, so plan step 5 shrinks it
before the default is chosen.

## Expected time

A simulation replayed the real access order of the 17-tree scan through a
graph cache: pass 1's three sweeps, every fixed-point round in the order the
resolver analysed functions, and the findings pass. It used each file's
measured graph size. One full parse of that configuration takes about 420
seconds, and the whole scan today takes 968.

| Budget | Order and policy | Extra rebuilding |
|---|---|---|
| 4GB | callees-first order, least recently used | 5.6 full parses |
| 4GB | grouped by file, least recently used | 5.2 full parses |
| 4GB | grouped by file, admit until full | **2.6 full parses** |
| 4GB | grouped by file, optimal (the lower bound) | 2.3 full parses |
| 2GB | grouped by file, admit until full | 4.3 full parses |

With the recommended order and policy, a 4GB budget adds about 1,100 seconds
to a 968-second scan, so about 2.1 times the run time, for about 2.5GB less
peak memory. Two things set that cost:

- **Callees-first order moves between files.** Round 1 alone touches files
  26,414 times under least recently used, more than there are files, because
  it returns to files it has just dropped. Grouping each round by file fixes
  most of that.
- **Every sweep over all files evicts everything under least recently used.**
  "Admit until full" keeps the files it already holds and rebuilds only the
  rest.

A scan whose graphs fit in the budget, like the benchmark, rebuilds nothing and
runs at today's speed.

The 168-tree configuration has not been simulated, because today's engine
cannot run it on this machine. With about a fifth of its graphs fitting in 4GB,
expect several full parses of extra rebuilding, and a full parse there is
roughly 1,400 seconds. Making graph building faster lowers this directly:
large reference files take about 23ms each on the 17-tree configuration, four
times the corpus average.

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

## What the first client run found

The first run of the 17-tree configuration at a 4GB budget took 1,430 seconds
to parse the reference trees, against about 420 expected. PHP's cycle
collector took most of it. PHP collects whenever ten thousand possible roots
have gathered, and each run walks what they reach, which in this scan is a
large part of the live graphs. Measured on the first 6,000 reference files:

| Configuration | Parse time | Collector time |
|---|---|---|
| No budget, automatic collector | 85s | 58s |
| 256MB budget, automatic collector | 57s | 29s |
| 256MB budget, collected every 500 files | 30s | 2.6s |

The collector was already costing today's engine most of its parse time. The
scan now turns automatic collection off and collects when the heap has grown by
a fixed step, checked between units of work.

The step was 256MB at first. On the 168-tree configuration, a sample of the
running scan showed about 65% of its time in the collector during the first
round, because each file rebuilt and dropped is garbage, and each collection
also walks the cached graphs the analysis has just touched. A 40-tree scan
measured both steps:

| Step | Parsing the reference trees | Collector time there | Peak heap |
|---|---|---|---|
| 256MB | 406s | 266s | 5.1GB |
| 1GB | 273s | 112s | 5.7GB |

The step is now 1GB. Up to 1GB of garbage can wait for the next collection, on
top of the budget.

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
3. **Stream pass 1.** Split setup into the three sweeps. Drop each file's graph
   and AST when its sweep is done.
   - **Gate:** identical, and pass 1's peak measured with `--debug-memory`.
4. **Budgeted pass 2.** Group each round by file, enable the admit-until-full
   cache in the resolver and the findings pass, and add `--memory-budget` with
   its 4GB default. Add a line to `--debug-memory` showing the floor, cache
   hits and rebuilds.
   - **Gate:** identical at several budgets. Record memory and time for the
     benchmark, and for the 17-tree and 168-tree client configurations.
5. **Shrink the floor.** Share one `TaintSet` instance per distinct value.
   `TaintSet` is an immutable object around one integer, and the tables hold a
   great many of them. Then measure which parts of the summaries remain
   largest, starting with trace steps and sink snippets.
   - **Gate:** identical, and the floor measured on the 17-tree configuration.
6. **Make graph building faster.** Large reference files take about 23ms each.
   Profile the build with SPX. Every millisecond saved there comes off the cost
   of a small budget.
   - **Gate:** identical graphs, checked by `tools/compare-simplifier.php` or a
     successor.

## Decisions

These were open in the first draft of this document.

- **The constant table: three sweeps.** Reproducing today's two constant
  passes needs a sweep for each, then one for edges. Keeping operands between
  sweeps instead would keep most of each graph alive, and the cache already
  absorbs much of the sweeps' cost.
- **Cache policy: admit until full, with each round grouped by file.** On the
  17-tree scan at 4GB, this costs 2.6 full parses of rebuilding, against 5.6 for
  least recently used in today's order and 2.3 for the theoretical optimum.
- **The floor: about 1.5GB on 17 trees, about 5GB projected on 168.** That is
  larger than the budget on the largest configuration, so step 5 shrinks it,
  starting with sharing `TaintSet` instances.
- **Default budget: 4GB of graph cache.** A scan whose graphs fit, like the
  benchmark, runs as fast as today. The 17-tree configuration drops from 7.97GB
  to about 5.5GB at about 2.1 times the run time. The 168-tree configuration
  drops from about 26GB to about 9GB. With `--jobs`, the 4GB is shared between
  the workers.
