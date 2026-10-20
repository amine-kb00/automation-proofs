# Shopify purchase tracking — idempotent Meta CAPI + GA4

Proof artifact built for the `[HIRING] Shopify tracking + n8n specialist` post
(community.n8n.io, topic 322445). It answers the question that post actually asks:
*"a Shopify tracking problem you fixed since Customer Events — what was wrong, and
how did you prove it was fixed."*

## The problem

Shopify retired **Additional Scripts** (`checkout.liquid`) in August 2025. Tracking
moved to **Customer Events** (sandboxed custom pixels + web pixels), and that move
broke the de-duplication contract most stores relied on:

1. The browser pixel fires `Purchase`.
2. A server-side call (CAPI / GA4 Measurement Protocol) fires `Purchase` again
   from a webhook.
3. Shopify **retries** the webhook when the endpoint is slow or returns non-2xx.

Without a shared `event_id`, steps 1–3 become 2–3 purchases for a single order.
Meta over-reports, ROAS drops, and the client "fixes" it by cutting budget.

## The fix implemented here

- `event_id` derived **deterministically** from the order
  (`sha256("purchase:" + order_id + ":" + currency + ":" + total)`), so the browser
  pixel and every server call agree on the same id — Meta deduplicates on
  `(event_name, event_id)`.
- **30-day idempotency window** in workflow static data: a retried delivery returns
  `{"skipped": true, "reason": "duplicate_event_id"}` and emits **nothing**.
- PII (email, customer id) is SHA-256 hashed before it leaves the workflow, as
  required by the CAPI contract.
- GA4 purchase event carries the same `transaction_id`, so GA4 deduplicates too.
- SHA-256 is implemented inline (the n8n Code node sandbox blocks `require('crypto')`).

## Files

| File | Role |
|---|---|
| `workflow.json` | n8n workflow (webhook → dedup → Meta CAPI + GA4), importable as-is |
| `code_node.js` | the dedup/payload code, kept readable outside the JSON |
| `mock_receiver.py` | stand-in for Meta/GA4 that records every POST it receives |
| `test_dedup.py` | the proof harness — 3 deliveries, 5 assertions |
| `proof_run.txt` | last real run output |
| `receipts.jsonl` | what actually left the workflow, byte for byte |

## Run it

```bash
# terminal 1 — fake Meta / GA4 sinks
python3 mock_receiver.py

# terminal 2 — n8n
N8N_USER_FOLDER=./tools/.n8n \
  node ./tools/node_modules/n8n/bin/n8n start

# import + activate (once)
N8N_USER_FOLDER=./tools/.n8n \
  node node_modules/n8n/bin/n8n import:workflow --input=workflow.json
N8N_USER_FOLDER=./tools/.n8n \
  node node_modules/n8n/bin/n8n update:workflow --id=shopifyPurchaseDedup1 --active=true
# restart n8n after activation, then:
python3 test_dedup.py
```

## Evidence (real run, `proof_run.txt`)

```
1st delivery  (order A)                HTTP 200  {"ok":true,"received":"/ga4"}
2nd delivery  (retry, order A)         HTTP 200  {"skipped":true,"reason":"duplicate_event_id",...}
3rd delivery  (order B)                HTTP 200  {"ok":true,"received":"/ga4"}

Outbound events emitted: 4
  POST /meta  -> bde772f554098afbefa37c4d6cd7b70c...
  POST /ga4   -> 1792497774
  POST /meta  -> 397db4893665561144fd0a4809f3695c...
  POST /ga4   -> 1792497775

  [PASS] retry acknowledged as duplicate
  [PASS] retry emitted nothing
  [PASS] exactly 2 Meta events
  [PASS] exactly 2 GA4 events
  [PASS] all payloads are valid JSON

PROOF HOLDS
```

Three deliveries, two unique orders, **four** outbound events. The retry produced zero.

## Honest limits (say these out loud to a client)

- The sinks here are local stand-ins. In production they become
  `https://graph.facebook.com/v21.0/<pixel_id>/events` (with `access_token`) and
  `https://www.google-analytics.com/mp/collect` (with `api_secret`).
- Static data is per n8n instance. On a multi-instance deployment the idempotency
  key belongs in Redis or Postgres, not in static data.
- This covers the *server* half of the contract. The browser pixel must send the
  same `event_id` for the dedup to bite — that is a 5-line change in the custom pixel.
