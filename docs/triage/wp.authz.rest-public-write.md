# Triage: `wp.authz.rest-public-write`

First slice of the finding-by-finding false-positive audit the benchmark doc
names as outstanding. Every corpus finding of this rule was read against its
source and classified.

**Result: 29 findings, 29 true positives, 0 false positives.**

## What the rule claims

A REST route handling a write method (`POST`, `PUT`, `PATCH`, `DELETE`, or the
`WP_REST_Server` constants for them) declared with `permission_callback =>
'__return_true'` — a route that changes state and is callable by anyone,
authenticated or not.

## Method

Each finding was dumped with fifteen lines of surrounding source and the
resolved method and permission callback. A finding is a true positive when the
route's methods include a write and its permission callback is `__return_true`
(or resolves to always-allow). The audit ran on the pinned corpus at commit
`28acc73`.

## Findings

All 29 are the same shape: a write method and `__return_true`.

| Plugin | Count | Methods | Note |
|--------|------:|---------|------|
| complianz-gdpr | 4 | POST | data-request and scan webhooks |
| jetpack | 5 | CREATABLE / EDITABLE | AI, connection, WC-analytics proxies |
| woocommerce | 4 | CREATABLE, `$methods` | mobile QR login, GraphQL — auth deferred to the handler |
| wordpress-seo | 4 | POST | AI-authorization JWT callbacks |
| wpforms-lite | 3 | `$methods` = `['POST']` | PayPal / Stripe / Square webhooks |
| hostinger-reach | 2 | POST | |
| contact-form-7 | 1 | CREATABLE | feedback submission |
| cookie-law-info | 1 | POST | |
| elementor | 1 | POST | |
| elementskit-lite | 1 | ALLMETHODS | includes every write |
| limit-login-attempts-reloaded | 1 | POST | MFA |
| mailchimp-for-wp | 1 | POST | |
| wordfence | 1 | CREATABLE | |

The `$methods` cases were checked to fold to a write: `['POST']` in WPForms,
`['POST']`/write in WooCommerce. The engine resolved each correctly; none was a
GET-only route mistaken for a write.

## The one nuance worth stating

Several of these are **webhooks and deferred-auth endpoints**: WooCommerce's
GraphQL controller comments "Auth is handled per-query/mutation", and the
payment webhooks verify a provider signature inside the callback rather than in
the permission callback. The rule flags the *shape* — a public write route —
which is accurate: the route is open at the WordPress layer, and whether the
handler re-establishes trust is exactly what a reviewer should check. These are
true positives that a reviewer may then accept, which is what the baseline is
for. They are not false positives: the rule does not claim exploitability, it
claims the permission callback authorises nothing.

## Verdict

The rule earns its severity. Nothing to change. The webhook nuance is worth a
line in the rule's remediation so a reviewer knows that "the callback checks a
signature" is a valid reason to baseline a finding — filed as a follow-up.
