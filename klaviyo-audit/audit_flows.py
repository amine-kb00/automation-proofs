#!/usr/bin/env python3
"""Klaviyo flow coverage audit.

Boston's post lists four flows by name — abandoned checkout, browse abandonment,
post-purchase, win-back — plus "health checks". A health check that cannot fail is
a sales deck. This one scores a store against rules that come from how Klaviyo
flows actually behave, and says "I cannot tell" when the data does not allow a
verdict instead of inventing one.

Input is the `/api/flows` response (or the same JSON saved from a client export):

    {"data": [{"id": "...", "attributes": {"name": "...", "status": "live",
               "trigger_type": "metric", "created": "...", "updated": "..."}}]}

Optional per-flow detail, when the export carries it:

    "steps": [{"type": "email", "delay_hours": 1}, {"type": "sms", "delay_hours": 24}]

    python3 audit_flows.py store.json [--json]

Exit 1 when a CRITICAL gap exists (a flow Klaviyo is supposed to have and does not,
or a flow that is silently in draft).
"""
import argparse
import json
import re
import sys

# Each requirement: how to recognise the flow, and what a healthy one looks like.
REQUIREMENTS = [
    {
        "key": "abandoned_checkout",
        "label": "Abandoned checkout",
        "match": r"checkout|cart|panier|carrito|warenkorb|basket",
        "severity": "CRITICAL",
        "min_emails": 2,
        "max_first_delay_hours": 24,
        "why": "the highest-ROI flow in almost every store; a checkout flow that starts "
               "after 24h has already lost the session",
    },
    {
        "key": "browse_abandonment",
        "label": "Browse abandonment",
        "match": r"browse|viewed product|navigation|produit vu",
        "severity": "HIGH",
        "min_emails": 1,
        "max_first_delay_hours": 6,
        "why": "catches the visitor who never reached checkout; worthless if it fires days later",
    },
    {
        "key": "welcome",
        "label": "Welcome series",
        "match": r"welcome|bienvenue|willkommen|bienvenid",
        "severity": "HIGH",
        "min_emails": 2,
        "max_first_delay_hours": 1,
        "why": "the only flow that runs while intent is at its peak — the signup itself",
    },
    {
        "key": "post_purchase",
        "label": "Post-purchase",
        "match": r"post.?purchase|thank.?you|order follow|review|avis|apr[eè]s achat",
        "severity": "HIGH",
        "min_emails": 1,
        "max_first_delay_hours": 24 * 14,
        "why": "kills 'where is my order' tickets and is the only legitimate place to ask for a review",
    },
    {
        "key": "winback",
        "label": "Win-back",
        "match": r"win.?back|re.?engage|reactivation|r[eé]activation|client perdu",
        "severity": "MEDIUM",
        "min_emails": 1,
        "max_first_delay_hours": 24 * 120,
        "why": "a repeat-purchase store without win-back pays acquisition cost twice",
    },
]


def norm(value):
    return (value or "").strip()


def steps_of(flow):
    """Return the channel/delay list, or None when the export is too thin."""
    raw = flow.get("steps") or flow.get("attributes", {}).get("steps")
    if not raw:
        return None
    out = []
    for s in raw:
        out.append({
            "type": norm(s.get("type") or s.get("action_type") or "unknown").lower(),
            "delay_hours": float(s.get("delay_hours", s.get("delay", 0)) or 0),
        })
    return out


def audit_flow(flow, rule):
    attrs = flow.get("attributes", {})
    name = norm(attrs.get("name") or flow.get("name"))
    status = norm(attrs.get("status") or flow.get("status")).lower()
    steps = steps_of(flow)
    findings, score = [], 100

    if status != "live":
        score -= 60
        findings.append(f"status is '{status or 'unknown'}', not live — the flow is built but not running")

    if steps is None:
        findings.append("step-level detail absent from this export: email count and first delay cannot be scored")
    else:
        emails = [s for s in steps if s["type"] in ("email", "message")]
        sms = [s for s in steps if s["type"] in ("sms", "text")]
        if len(emails) < rule["min_emails"]:
            score -= 30
            findings.append(f"{len(emails)} email(s), expected at least {rule['min_emails']}")
        if emails:
            first = min(s["delay_hours"] for s in emails)
            if first > rule["max_first_delay_hours"]:
                score -= 25
                findings.append(f"first email after {first:g}h, too late for this flow (target ≤ {rule['max_first_delay_hours']}h)")
            elif first == 0:
                findings.append("first email fires immediately — no delay means no recovery window")
        if rule["key"] == "abandoned_checkout" and not sms:
            score -= 5
            findings.append("no SMS step; on mobile checkouts SMS is the step that converts")

    if steps is None:
        # No step data: a live flow is plausible but unproven. Saying "OK" here is
        # how an audit starts lying, so the verdict is explicitly unscored.
        return {"name": name, "status": status or "unknown", "score": None,
                "verdict": "UNSCORED" if status == "live" else "BROKEN", "findings": findings}

    return {"name": name, "status": status or "unknown", "score": max(score, 0),
            "verdict": "OK" if score >= 90 else "WEAK" if score >= 60 else "BROKEN",
            "findings": findings}


def audit(store):
    flows = store.get("data") or store.get("flows") or []
    report = {"store": store.get("store") or store.get("domain") or "unknown",
              "flows_seen": len(flows), "requirements": [], "unmatched_flows": []}

    used = set()
    for rule in REQUIREMENTS:
        pattern = re.compile(rule["match"], re.I)
        matches = [f for f in flows
                   if pattern.search(norm(f.get("attributes", {}).get("name") or f.get("name")))]
        entry = {"key": rule["key"], "label": rule["label"], "severity": rule["severity"],
                 "flows": [audit_flow(f, rule) for f in matches],
                 "why": rule["why"]}
        if not matches:
            entry["verdict"] = "MISSING"
        else:
            scored = [f for f in entry["flows"] if f["score"] is not None]
            entry["verdict"] = max(scored, key=lambda f: f["score"])["verdict"] if scored else "UNSCORED"
        report["requirements"].append(entry)
        for f in matches:
            used.add(id(f))

    report["unmatched_flows"] = [
        norm(f.get("attributes", {}).get("name") or f.get("name"))
        for f in flows if id(f) not in used
    ]

    critical = [r for r in report["requirements"]
                if r["verdict"] in ("MISSING", "BROKEN", "UNSCORED") and r["severity"] == "CRITICAL"]
    report["ok"] = not critical
    report["critical_gaps"] = [r["label"] for r in critical]
    return report


def render(report):
    lines = [f"{report['store']} — {report['flows_seen']} flows", ""]
    for req in report["requirements"]:
        lines.append(f"  {req['label']:<20} {req['verdict']:<8} ({req['severity']})")
        for flow in req["flows"]:
            score = "n/a" if flow["score"] is None else flow["score"]
            lines.append(f"      {flow['name']!r}  status={flow['status']}  score={score}")
            for finding in flow["findings"]:
                lines.append(f"        - {finding}")
        if req["verdict"] == "MISSING":
            lines.append(f"        - no flow matches this trigger. {req['why']}")
    if report["unmatched_flows"]:
        lines.append("")
        lines.append("  also present: " + ", ".join(report["unmatched_flows"][:8]))
    lines.append("")
    lines.append("VERDICT: " + ("PASS" if report["ok"] else "FAIL — " + ", ".join(report["critical_gaps"])))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    reports = []
    for path in args.files:
        with open(path) as fh:
            reports.append(audit(json.load(fh)))
    if args.json:
        print(json.dumps(reports, indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(render(r) for r in reports))
    return 0 if all(r["ok"] for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
