# Proofs that run

Four automation checks, each with a case that fails on purpose.

| case | verdict | proves |
|---|---|---|
| dmarc: aggregate reports | PASS | 98 spoofed messages, `p=none` blocks nothing |
| klaviyo: flows (healthy) | PASS | 5/5 ok — control case |
| klaviyo: flows (broken) | PASS | draft checkout, 48 h delay, 3 missing |
| klaviyo: flows (thin export) | PASS | `UNSCORED` must not pass |
| dns: shopify.com | PASS | real dig, `p=reject` → WARN allowed |
| dns: gate closes (example.com) | PASS | revoked DKIM → FAIL → exit 1 |
| n8n: shopify dedup | PASS | 3 deliveries → 4 events, retry 0 |
| n8n: deliverability webhook | PASS | 8/8 assertions |

```
bash run_all.sh           # 6 checks need python3 + dig
bash run_all.sh --strict  # SKIP becomes a failure
```

The two n8n checks need a local instance:

```
cd tools && N8N_PORT=5678 N8N_HOST=127.0.0.1 N8N_SECURE_COOKIE=false \
  N8N_USER_FOLDER=$PWD/.n8n NODES_EXCLUDE= node node_modules/n8n/bin/n8n start
```

Not run against a live client store. Fixtures are synthetic; see the honesty section on the page and the
README of each folder. MIT.
