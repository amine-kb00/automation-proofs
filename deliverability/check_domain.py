#!/usr/bin/env python3
"""Email deliverability audit: SPF (with the 10-DNS-lookup ceiling), DKIM
selectors, DMARC policy, MX. Pure stdlib + dig, no API key, no dependency.

This is the first half of a "Klaviyo health check" that can actually fail:
a store can have beautiful flows and still land in spam.

    python3 check_domain.py example.com [--json] [--selectors k1,s1,klaviyo]

Exit code 0 when every check passes, 1 when at least one FAILs, so the same
script can gate an n8n workflow.
"""
import argparse
import json
import re
import subprocess
import sys

MAX_LOOKUPS = 10
MAX_VOID = 2

DEFAULT_SELECTORS = [
    "default", "google", "k1", "k2", "s1", "s2", "mail", "smtp",
    "klaviyo", "kl", "selector1", "selector2", "mandrill", "sendgrid",
    "shopify", "cm", "protonmail", "mailchimp",
]


def dig(name, rtype, timeout=6):
    """Return the RDATA strings of a DNS answer, [] when absent/on error."""
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", name, rtype],
            capture_output=True, text=True, timeout=timeout,
        ).stdout
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        # A TXT record longer than 255 bytes is published as several quoted
        # character-strings; their concatenation IS the record (RFC 1035 §3.3.14).
        # Joining them is what makes long SPF/DMARC records readable at all.
        chunks = re.findall(r'"([^"]*)"', line)
        rows.append("".join(chunks) if chunks else line)
    return rows


# --------------------------------------------------------------------------- SPF

SPF_MECH = re.compile(
    # longest alternatives first: 'all' must win over 'a', 'ip4' over 'ip'
    r"^(?P<qual>[+\-~?]?)(?P<name>include|exists|ip4|ip6|ptr|mx|all|a)"
    r"(?P<sep>[:=/])?(?P<arg>.*)$",
    re.I,
)


def parse_spf(record):
    """Split an SPF record into its terms, dropping the version token."""
    terms = record.split()[1:]
    parsed = []
    for t in terms:
        m = SPF_MECH.match(t)
        if not m:
            parsed.append({"raw": t, "name": "?", "qual": "", "arg": ""})
            continue
        parsed.append({
            "raw": t,
            "qual": m.group("qual") or "+",
            "name": m.group("name").lower(),
            "arg": m.group("arg") or "",
        })
    return parsed


def count_lookups(domain, record, seen, counter, depth=0):
    """Walk the SPF tree, counting DNS-lookup terms the way RFC 7208 §4.6.4 does.

    include / a / mx / ptr / exists / redirect each cost one lookup; a nested
    include recurses, which is exactly how a store ends up over the limit
    without anyone noticing.
    """
    if depth > 5:
        return
    for term in parse_spf(record):
        name = term["name"]
        if name in ("include", "a", "mx", "ptr", "exists"):
            counter["lookups"] += 1
            if name in ("a", "mx") and "/" in term["arg"]:
                counter["lookups"] += 1          # a CIDR (a/24, mx/24) costs two lookups
        if name == "redirect":
            counter["lookups"] += 1
            target = term["arg"]
            if target and target not in seen:
                seen.add(target)
                nxt = spf_record(target)
                if nxt:
                    count_lookups(target, nxt, seen, counter, depth + 1)
        if name == "include" and term["arg"]:
            target = term["arg"]
            if target in seen:
                continue
            seen.add(target)
            nxt = spf_record(target)
            if not nxt:
                counter["void"] += 1
                counter["broken_includes"].append(target)
            else:
                count_lookups(target, nxt, seen, counter, depth + 1)


def spf_record(domain):
    for txt in dig(domain, "TXT"):
        if txt.lower().startswith("v=spf1"):
            return txt
    return ""


def audit_spf(domain):
    records = [t for t in dig(domain, "TXT") if t.lower().startswith("v=spf1")]
    res = {"domain": domain, "found": [], "verdict": "PASS", "notes": []}
    if not records:
        res["verdict"] = "FAIL"
        res["notes"].append("no SPF record — receivers fall back to the SPF of nothing at all, DMARC alignment dies")
        return res
    if len(records) > 1:
        res["verdict"] = "FAIL"
        res["notes"].append(f"{len(records)} SPF records — RFC 7208 forbids it, receivers return permerror")
    rec = records[0]
    res["found"] = records

    counter = {"lookups": 0, "void": 0, "broken_includes": []}
    count_lookups(domain, rec, {domain}, counter)
    res["lookups"] = counter["lookups"]
    res["broken_includes"] = counter["broken_includes"]

    if counter["lookups"] > MAX_LOOKUPS:
        res["verdict"] = "FAIL"
        res["notes"].append(f"{counter['lookups']} DNS lookups > {MAX_LOOKUPS} — permerror, every message fails SPF")
    elif counter["lookups"] >= 8:
        res["notes"].append(f"{counter['lookups']} DNS lookups — dangerously close to the {MAX_LOOKUPS} ceiling")
    if counter["broken_includes"]:
        res["notes"].append(f"{len(counter['broken_includes'])} include(s) resolve to no SPF: {', '.join(counter['broken_includes'][:4])}")

    terms = parse_spf(rec)
    all_term = next((t for t in terms if t["name"] == "all"), None)
    if not all_term:
        res["verdict"] = "FAIL"
        res["notes"].append("no 'all' mechanism — the record is ambiguous")
    else:
        res["all"] = all_term["raw"]
        if all_term["qual"] == "?":
            res["verdict"] = "FAIL"
            res["notes"].append("'?all' is neutral — SPF asserts nothing, spoofing is not discouraged")
        elif all_term["qual"] in ("~", ""):
            if res["verdict"] == "PASS":
                res["verdict"] = "WARN"
            res["notes"].append(f"'{all_term['raw']}' soft-fails; only '-all' refuses unauthorised senders")
    res["record"] = rec
    return res


# ------------------------------------------------------------------------- DMARC

def audit_dmarc(domain):
    res = {"domain": domain, "verdict": "PASS", "notes": []}
    rows = [t for t in dig(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    if not rows:
        res["verdict"] = "FAIL"
        res["notes"].append("no DMARC record — no policy, no reporting, receivers guess")
        return res
    rec = rows[0]
    res["record"] = rec
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    res["tags"] = tags
    policy = tags.get("p", "").lower()
    res["policy"] = policy
    if policy == "none":
        res["verdict"] = "WARN"
        res["notes"].append("p=none — monitoring only, a spoofed message is still delivered")
    elif policy not in ("quarantine", "reject"):
        res["verdict"] = "FAIL"
        res["notes"].append(f"p={policy or 'absent'} is not a valid policy")
    if "rua" not in tags:
        if res["verdict"] == "PASS":
            res["verdict"] = "WARN"
        res["notes"].append("no rua= — nobody receives the aggregate reports, so the policy can never be tightened safely")
    pct = tags.get("pct")
    if pct and pct != "100":
        res["notes"].append(f"pct={pct} — policy applied to only {pct}% of mail")
    return res


# -------------------------------------------------------------------------- DKIM

def audit_dkim(domain, selectors):
    res = {"domain": domain, "verdict": "FAIL", "found": [], "notes": []}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        for txt in dig(name, "TXT"):
            flat = txt.replace(" ", "")
            if "p=" not in flat:
                continue
            key = flat.split("p=", 1)[1].split(";")[0]
            entry = {"selector": sel, "bits": len(key) * 6 if key else 0, "record": flat[:120]}
            res["found"].append(entry)
            if key and len(key) * 6 < 1024:
                res["notes"].append(f"{sel}: key looks shorter than 1024 bits")
            elif key:
                res["verdict"] = "PASS"
    revoked = [f["selector"] for f in res["found"] if not f["bits"]]
    usable = [f for f in res["found"] if f["bits"]]
    if revoked and not usable:
        res["verdict"] = "FAIL"
        res["notes"].append(
            f"{len(revoked)} selector(s) resolve to an empty p= — the key is revoked, "
            "so this domain cannot sign at all"
        )
    elif revoked:
        res["notes"].append(f"{len(revoked)} revoked selector(s) also published: {', '.join(revoked[:5])}")
    if not res["found"]:
        res["verdict"] = "WARN"
        res["notes"].append(
            "no key on the common selectors — this is not proof of failure: Klaviyo and "
            "Shopify often publish a custom selector. Ask the client for it, then re-run "
            "with --selectors"
        )
    return res


def audit_mx(domain):
    res = {"domain": domain, "verdict": "PASS", "hosts": []}
    rows = dig(domain, "MX")
    res["hosts"] = rows
    if not rows:
        res["verdict"] = "FAIL"
        res["notes"] = ["no MX — the domain cannot receive bounces or replies"]
    return res


# -------------------------------------------------------------------------- main

def audit(domain, selectors=None):
    selectors = selectors or DEFAULT_SELECTORS
    report = {
        "domain": domain,
        "mx": audit_mx(domain),
        "spf": audit_spf(domain),
        "dkim": audit_dkim(domain, selectors),
        "dmarc": audit_dmarc(domain),
    }
    verdicts = [report[k]["verdict"] for k in ("mx", "spf", "dkim", "dmarc")]
    if "FAIL" in verdicts:
        report["verdict"] = "FAIL"
    elif "WARN" in verdicts:
        report["verdict"] = "WARN"
    else:
        report["verdict"] = "PASS"
    return report


def render(report):
    lines = [f"{report['domain']}  →  {report['verdict']}", ""]
    for key in ("mx", "spf", "dkim", "dmarc"):
        block = report[key]
        lines.append(f"  {key.upper():<6} {block['verdict']}")
        if key == "spf" and block.get("lookups") is not None:
            lines.append(f"         {block['lookups']}/{MAX_LOOKUPS} DNS lookups, all={block.get('all', 'absent')}")
        if key == "dmarc" and block.get("policy"):
            lines.append(f"         p={block['policy']}")
        if key == "dkim" and block.get("found"):
            sels = ", ".join(f"{f['selector']}(~{f['bits']}b)" for f in block["found"])
            lines.append(f"         selectors: {sels}")
        for note in block.get("notes", []):
            lines.append(f"         - {note}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domains", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selectors", default="")
    args = ap.parse_args()
    selectors = [s.strip() for s in args.selectors.split(",") if s.strip()] or None

    reports = [audit(d.strip().lower(), selectors) for d in args.domains]
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print("\n".join(render(r) for r in reports))
    # Gate semantics: WARN is reportable, FAIL blocks. A CI job that fails on a
    # soft-fail policy would cry wolf on half the internet.
    return 0 if all(r["verdict"] != "FAIL" for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
