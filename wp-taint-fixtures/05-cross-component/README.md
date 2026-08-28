# Cross-component taint fixtures

These probe the hardest capability: taint that enters in one component and
reaches a sink in a *different* component, connected only by the WordPress hook
system or shared persistence. A single-file analyser cannot see these; the
engine must resolve `do_action`/`apply_filters` names to their `add_action`/
`add_filter` handlers across the whole scanned tree.

Three linked components:

- `plugin-a/` — collects input, stores it, and fires a custom action carrying
  a raw value.
- `plugin-b/` — hooks plugin-a's action and echoes the payload (the sink).
- `theme/` — reads plugin-a's stored option and renders it in a template.

Expected findings span files: the source is in one file, the sink in another.
