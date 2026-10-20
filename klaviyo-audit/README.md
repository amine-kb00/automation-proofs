# Klaviyo flow audit

Third piece of the same job: the post names four flows — abandoned checkout, browse
abandonment, post-purchase, win-back — and calls the rest "health checks".

A health check that cannot fail is a sales deck. This one scores a store against
rules taken from how Klaviyo flows actually behave, and it refuses to invent a
verdict when the export does not carry the data.

    python3 audit_flows.py fixtures/broken.json [--json]

Exit `1` on a critical gap, `0` otherwise, so it can gate a pipeline.

## What is scored

| Flow | Severity | Rules |
|---|---|---|
| Abandoned checkout | CRITICAL | live, ≥2 emails, first email ≤24h, an SMS step |
| Browse abandonment | HIGH | live, ≥1 email, first email ≤6h |
| Welcome series | HIGH | live, ≥2 emails, first email ≤1h |
| Post-purchase | HIGH | live, ≥1 email, first email ≤14 days |
| Win-back | MEDIUM | live, ≥1 email, first email ≤120 days |

Scoring starts at 100: not live → −60, too few emails → −30, first email too late →
−25, checkout flow without SMS → −5. `≥90 OK`, `≥60 WEAK`, else `BROKEN`.

Flow recognition is by name regex (`checkout|cart|panier|…`), because Klaviyo's own
template is literally called **"Abandoned Cart"** — an audit that only matches the
word "checkout" reports a missing flow that is sitting right there in draft. That
was a real bug found by running the fixture, not by reading the code.

## Evidence (`proof_run.txt`)

```
broken-store.com — 3 flows
  Abandoned checkout   BROKEN   (CRITICAL)
      'Abandoned Cart'  status=draft  score=10
        - status is 'draft', not live — the flow is built but not running
        - first email after 48h, too late for this flow (target ≤ 24h)
        - no SMS step
  Browse abandonment   MISSING  (HIGH)
  Welcome series       WEAK     (HIGH)   1 email, fires immediately
  Post-purchase        MISSING  (HIGH)
  Win-back             MISSING  (MEDIUM)
VERDICT: FAIL — Abandoned checkout

healthy-store.com — 5 flows      VERDICT: PASS      (exit 0)

thin-export.com — 1 flows
  Abandoned checkout   UNSCORED (CRITICAL)
        - step-level detail absent: email count and first delay cannot be scored
VERDICT: FAIL — Abandoned checkout
```

The third case is the one that matters: a live flow with no step data is **not** a
pass. `UNSCORED` is a first-class verdict, and a critical `UNSCORED` fails the store
exactly like a missing flow does. Otherwise the audit silently green-lights the
half of the estate nobody looked at.

## Honest limits

- `GET /api/flows` returns flow metadata, **not** the step tree. Real step scoring
  needs `/api/flows/{id}/actions` (or the export that carries `steps`), so the tool
  says `UNSCORED` rather than guessing from the flow name.
- Recognition is a name heuristic. A store that names a checkout flow "Recover" will
  read as missing — the fix is a per-client mapping, not a bigger regex.
- Thresholds are opinionated defaults, not Klaviyo doctrine. They are arguments to
  change in conversation with the client, and saying so is cheaper than being
  wrong in silence.
