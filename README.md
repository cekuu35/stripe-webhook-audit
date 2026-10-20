# stripe-webhook-audit

[![CI](https://github.com/cekuu35/stripe-webhook-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cekuu35/stripe-webhook-audit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/stripe-webhook-audit.svg)](https://www.npmjs.com/package/stripe-webhook-audit)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Scan a codebase for **Stripe webhook handlers that trust events without
signature verification**.

An unverified Stripe webhook is a business-logic backdoor: anyone who finds
the URL can POST forged events — `charge.succeeded`, `customer.subscription
updated`, refund confirmations — and your code will act on them as if Stripe
sent them. The failure is a missing *one-liner*
(`stripe.webhooks.constructEvent(...)`), so it survives review and often
ships because a tutorial skipped it or a body parser ate the raw payload.

Zero dependencies. Reads nothing from the network. **Free, forever.**

## Quick start

```bash
npx stripe-webhook-audit            # scans the current directory
npx stripe-webhook-audit ../api --json
```

Walks `.js/.ts/.jsx/.tsx/.mjs/.cjs` sources, skipping `node_modules`,
`.git`, `dist`, `build`, `.next`.

Exit codes are CI-friendly: `0` clean, `1` any critical/high finding.

## What it detects

| Rule | Severity | What it catches |
|---|---|---|
| `NO_SIGNATURE_CHECK` | critical | a Stripe webhook handler with no `constructEvent` call — especially the `JSON.parse(req.body)` shortcut, which forges events from anyone who finds the URL |
| `HARDCODED_WEBHOOK_SECRET` | high | a `whsec_...` literal in source — move to env; rotate if it was ever committed |
| `BODY_PARSER_BEFORE_WEBHOOK` | medium | `express.json()` / `bodyParser.json()` in the same file as a verified webhook — `constructEvent` needs the RAW body, and a parsed body makes verification fail (which tempts people to delete it) |
| `SECRET_SOURCE_UNKNOWN` | low | verification present but no discoverable secret source in the file — confirm it comes from configuration |

Files without both `stripe` and `webhook` markers are never scanned, so
ordinary JSON endpoints are not flagged.

## Example output

Scanning the [broken example](examples/broken/webhook.js):

```
== examples/broken (1 source files scanned)
   [CRITICAL] NO_SIGNATURE_CHECK - webhook.js
       this file handles Stripe webhook events via JSON.parse on the raw body without any signature verification — anyone who finds the URL can forge events (charges, refunds, subscription changes)
       evidence: JSON.parse(body) + no constructEvent
   [HIGH] HARDCODED_WEBHOOK_SECRET - webhook.js
       a Stripe webhook signing secret (whsec_...) is hardcoded — move it to an environment variable; rotate it if it was ever committed
       evidence: whsec_***(38 chars)

Summary: 1 critical, 1 high, 0 medium, 0 low
```

## Tests

```bash
npm test
```

6 tests, zero dependencies: both rules fire on the broken fixture, the
clean fixture (`constructEvent` + env secret + `express.raw`) stays clean,
the low-trust "secret source unknown" case flags as low, body-parser
coexistence flags as a hint, non-Stripe endpoints are never touched, and
evidence never contains the full `whsec_` value.

## The correct handler, for reference

```js
router.post('/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch {
    return res.status(400).send('Webhook signature verification failed.');
  }
  res.json({ received: true });
});
```

## Honest scope

This is a static linter, not a payment-security audit. It does not exercise
your routes, verify idempotency handling, check event ordering, or audit
what your handler does after verification. A handler can pass this scan and
still misbehave. Verify manually against Stripe's test events after fixing
anything.

## The audit family

Free, zero-dependency security auditors in the same shape:

- [mcp-config-security](https://github.com/cekuu35/mcp-config-security) — scan MCP client configs (Claude, Cursor, Windsurf) for leaked tokens
- [supabase-service-role-scanner](https://github.com/cekuu35/supabase-service-role-scanner) — find Supabase service_role keys exposed to the browser
- [github-actions-audit](https://github.com/cekuu35/github-actions-audit) — pwn requests, script injection and unpinned actions in CI
- [firebase-rules-audit](https://github.com/cekuu35/firebase-rules-audit) — open access in Firestore / Storage rules
- [n8n-workflow-audit](https://github.com/cekuu35/n8n-workflow-audit) — hardcoded credentials and open webhooks in exported n8n workflows
- [supabase-rls-leak-demo](https://github.com/cekuu35/supabase-rls-leak-demo) — red/green fixture proving a Supabase RLS leak, and its one-file fix

## Support

If this tool caught an unverified webhook before a forged event did, you
can [buy me a coffee](https://www.buymeacoffee.com/cenkkurtoglu) —
completely optional. The tool is free, no features are locked, and no email
is asked.

## License

MIT
