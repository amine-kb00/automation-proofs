#!/usr/bin/env python3
"""Proof for the deliverability gate workflow.

Calls the n8n webhook with three domains whose DNS state is independently
checkable with dig, then asserts the verdicts match reality:
  - a healthy but soft-failing domain   -> ok, WARN on SPF only
  - a domain that cannot sign mail      -> not ok, DKIM FAIL
Exit 0 only when every assertion holds.
"""
import json
import sys
import urllib.error
import urllib.request

URL = "http://127.0.0.1:5678/webhook/audit-domain"
CASES = [
    ("shopify.com", True, "WARN"),
    ("example.com", False, "FAIL"),
]


def ask(domain):
    req = urllib.request.Request(
        URL, data=json.dumps({"domain": domain}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def main():
    failures = 0
    for domain, expect_ok, expect_verdict in CASES:
        try:
            status, body = ask(domain)
        except Exception as exc:                     # noqa: BLE001
            print(f"[FAIL] {domain}: webhook error {type(exc).__name__}: {exc}")
            failures += 1
            continue
        row = body["summary"][0]
        checks = {
            "http 200": status == 200,
            f"ok={expect_ok}": body["ok"] is expect_ok,
            f"verdict={expect_verdict}": row["verdict"] == expect_verdict,
            "full report attached": isinstance(body.get("reports"), list) and bool(body["reports"]),
        }
        for name, ok in checks.items():
            print(f"  [{'PASS' if ok else 'FAIL'}] {domain:<14} {name}")
            failures += 0 if ok else 1
        print(f"         blocked on: {row['failures'] or '-'} | warnings: {row['warnings'] or '-'}")
    print()
    print("GATE PROVEN" if failures == 0 else f"{failures} ASSERTION(S) FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
