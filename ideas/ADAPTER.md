# Adapter contract

The suite is analyser-agnostic. Add a small adapter from your analyser's native output to this normalized form:

```json
[
  {"fixture":"I01","variant":"vulnerable","kind":"input.unsanitized_storage"},
  {"fixture":"O10","variant":"vulnerable","kind":"output.escape_invalidated"}
]
```

## Mapping guidance

If your analyser has one broad rule such as `xss`, map based on the fixture expectation rather than weakening the fixture corpus. Prefer evolving the analyser to emit the more precise classification over time.

For path findings, the comparator intentionally does not require exact source/sink line numbers. Different engines anchor findings differently. The per-variant `expected.json` files retain marker lines so you can add a stricter path/line comparator later.

## Important semantic rules

- `wp_unslash()` is a propagator, not a sanitizer.
- `shortcode_atts()` is a propagator/defaulting helper, not a sanitizer.
- nonce/capability checks affect authorization/integrity, not content taint.
- database reads are untrusted for output.
- input sanitizers do not satisfy output escaping requirements.
- an escaper is valid only for the context it protects.
- `apply_filters()` after escaping invalidates the escape state.
- benign string operations (`trim`, `strtolower`, `sprintf`, concatenation) propagate taint unless every dynamic operand is safe for the resulting context.
