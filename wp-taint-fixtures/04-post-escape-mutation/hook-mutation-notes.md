# Why the `04-post-escape-mutation` set exists

These fixtures encode the house rule that most third-party analysers miss:

> Once output is escaped, it must not become user-modifiable again. If an
> escaped value passes through a hook, filter, shortcode expansion, or any
> other mutation point before it reaches the sink, the escape is void.

A checker that only asks "is there an `esc_*` call on the path?" will score
every file here as safe and miss real bugs. The correct model is:

1. Track the *position* of the escape relative to the sink.
2. Treat `apply_filters`, `do_shortcode`, and equivalent extension points as
   taint *re-introduction* points, not neutral pass-throughs.
3. Require that the escape be the **last** transformation before the sink.

Expected: every `ruleid: wp.output.escape-voided` line is a true positive;
every `ok:` line is a true negative.
