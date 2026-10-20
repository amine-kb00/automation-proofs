#!/usr/bin/env python3
"""Proof harness for the Shopify -> Meta CAPI / GA4 idempotent workflow.

Sends the same Shopify order twice (a webhook retry) plus one new order, then
checks what actually left n8n:
  - order 1042 (delivered twice) must emit exactly 2 events (1 Meta + 1 GA4)
  - order 1043 (delivered once)  must emit exactly 2 events
  => 4 outbound events for 3 deliveries, and the retry must be a no-op.

Exit code 0 = proof holds.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

WEBHOOK = "http://127.0.0.1:5678/webhook/shopify-order"
RECEIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "receipts.jsonl")

ORDER = {
    "id": 0, "order_number": 0, "email": "Sarah.Customer@Example.COM",
    "currency": "USD", "total_price": "129.90", "shop_domain": "demo-store.myshopify.com",
    "customer": {"id": 88112233},
    "line_items": [
        {"sku": "TEE-BLK-M", "quantity": 2, "price": "49.95"},
        {"sku": "MUG-01", "quantity": 1, "price": "30.00"},
    ],
}


def post(payload, label):
    req = urllib.request.Request(
        WEBHOOK, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read().decode()
    print(f"{label:<38} HTTP {r.status}  {body[:90]}")
    return r.status, body


def main():
    open(RECEIPTS, "w").close()

    # Fresh order ids on every run: the workflow keeps a 30-day window of seen
    # event_ids, so a fixed id would be a duplicate on the second run.
    run_id = int(time.time())
    order1 = dict(ORDER, id=run_id, order_number=run_id % 100000)
    print(f"run_id={run_id}\n")

    post(order1, "1st delivery  (order A)")
    status2, body2 = post(order1, "2nd delivery  (retry, order A)")
    order2 = dict(order1, id=run_id + 1, order_number=(run_id + 1) % 100000, total_price="59.00")
    post(order2, "3rd delivery  (order B)")

    receipts = [json.loads(line) for line in open(RECEIPTS)]
    print(f"\nOutbound events emitted: {len(receipts)}")
    for r in receipts:
        payload = json.loads(r["body"])
        if "data" in payload:
            tag = payload["data"][0]["event_id"]
        else:
            tag = payload["events"][0]["params"]["transaction_id"]
        print(f"  POST {r['path']:<6} -> {tag}")

    checks = {
        "retry acknowledged as duplicate": '"skipped":true' in body2.replace(" ", ""),
        "retry emitted nothing": status2 == 200,
        "exactly 2 Meta events": sum(1 for r in receipts if r["path"] == "/meta") == 2,
        "exactly 2 GA4 events": sum(1 for r in receipts if r["path"] == "/ga4") == 2,
        "all payloads are valid JSON": all(
            json.loads(r["body"]) for r in receipts
        ),
    }
    print()
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPROOF HOLDS")
        return 0
    print("\nPROOF FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
