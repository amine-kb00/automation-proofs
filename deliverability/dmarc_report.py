#!/usr/bin/env python3
"""DMARC aggregate report ("rua") analyser.

A DMARC aggregate report answers one question no other source can: *who actually
sends mail as your domain, and do they authenticate?* Everything else — SPF/DKIM
records, policies — is what you declared. This is what happened.

    python3 dmarc_report.py report.xml [more.xml.gz ...] [--json]

Reads plain or gzipped XML (the three big reporters — Google, Microsoft, Yahoo —
all send .gz), groups by source IP, and separates three populations that people
constantly mix up:

  PASS     aligned authentication: a legitimate sender
  UNALIGN  authenticated somewhere, but not as *your* domain (a forwarder, a
           mailing list, an ESP with its own DKIM domain)
  SPOOF    failed SPF *and* DKIM, with your domain in From: — someone is either
           spoofing you or a legitimate sender is badly configured

Exit code 1 when spoofing appears while the published policy is p=none: mail is
being forged and the DNS still tells receivers to deliver it.
"""
import argparse
import gzip
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict


def load_xml(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as fh:
        return fh.read()


def strip_ns(elem):
    """Reporters disagree on namespaces; local names are the stable contract."""
    for e in elem.iter():
        if "}" in e.tag:
            e.tag = e.tag.split("}", 1)[1]
    return elem


def parse_report(raw):
    root = strip_ns(ET.fromstring(raw))
    meta = root.find("report_metadata")
    published = root.find("policy_published")

    def text(node, path, default=""):
        found = node.find(path) if node is not None else None
        return (found.text or default) if found is not None else default

    report = {
        "org": text(meta, "org_name"),
        "report_id": text(meta, "report_id"),
        "range_begin": text(meta, "date_range/begin"),
        "range_end": text(meta, "date_range/end"),
        "domain": text(published, "domain"),
        "policy": text(published, "p"),
        "pct": text(published, "pct", "100"),
        "records": [],
    }

    for rec in root.findall("record"):
        row = rec.find("row")
        evaluated = row.find("policy_evaluated") if row is not None else None
        auth = rec.find("auth_results")
        dkim_domains = [d.text for d in rec.findall("auth_results/dkim/domain") if d.text]
        spf_domains = [d.text for d in rec.findall("auth_results/spf/domain") if d.text]
        report["records"].append({
            "ip": text(row, "source_ip"),
            "count": int(text(row, "count", "1") or 1),
            "disposition": text(evaluated, "disposition"),
            "dkim": text(evaluated, "dkim"),
            "spf": text(evaluated, "spf"),
            "header_from": text(rec, "identifiers/header_from"),
            "dkim_domains": dkim_domains,
            "spf_domains": spf_domains,
            "dkim_auth": [r.text for r in auth.findall("dkim/result")] if auth is not None else [],
            "spf_auth": [r.text for r in auth.findall("spf/result")] if auth is not None else [],
        })
    return report


def classify(record, domain):
    """Bucket one aggregate row. Alignment, not raw auth, is what DMARC scores."""
    aligned_dkim = any(d == domain or d.endswith("." + domain) for d in record["dkim_domains"]) and record["dkim"] == "pass"
    aligned_spf = any(d == domain or d.endswith("." + domain) for d in record["spf_domains"]) and record["spf"] == "pass"
    if aligned_dkim or aligned_spf:
        return "PASS"
    if record["dkim"] == "pass" or record["spf"] == "pass":
        return "UNALIGN"
    return "SPOOF"


def analyse(reports):
    per_ip = defaultdict(lambda: {"count": 0, "PASS": 0, "UNALIGN": 0, "SPOOF": 0,
                                  "dispositions": set(), "header_froms": set(),
                                  "auth_domains": set()})
    published = {}
    for rep in reports:
        domain = rep["domain"]
        published.setdefault(domain, {"policy": rep["policy"], "pct": rep["pct"],
                                       "reporters": set()})
        published[domain]["reporters"].add(rep["org"])
        for rec in rep["records"]:
            bucket = classify(rec, domain)
            entry = per_ip[rec["ip"]]
            entry["count"] += rec["count"]
            entry[bucket] += rec["count"]
            if rec["disposition"]:
                entry["dispositions"].add(rec["disposition"])
            if rec["header_from"]:
                entry["header_froms"].add(rec["header_from"])
            entry["auth_domains"].update(rec["dkim_domains"] + rec["spf_domains"])

    result = {"domains": {}, "sources": []}
    for domain, info in published.items():
        spoofed = sum(e["SPOOF"] for e in per_ip.values())
        result["domains"][domain] = {
            "policy": info["policy"],
            "pct": info["pct"],
            "reporters": sorted(info["reporters"]),
            "spoofed_messages": spoofed,
            "policy_is_enforcing": info["policy"] in ("quarantine", "reject"),
        }
    for ip, e in sorted(per_ip.items(), key=lambda kv: -kv[1]["count"]):
        total = e["count"] or 1
        result["sources"].append({
            "ip": ip,
            "messages": e["count"],
            "pass_pct": round(100 * e["PASS"] / total),
            "unaligned_pct": round(100 * e["UNALIGN"] / total),
            "spoof_pct": round(100 * e["SPOOF"] / total),
            "class": (
                "SPOOF" if e["SPOOF"] == e["count"]
                else "PASS" if e["PASS"] == e["count"]
                else "UNALIGN" if e["UNALIGN"] == e["count"]
                else "MIXED"
            ),
            "header_from": sorted(e["header_froms"]),
            "auth_domains": sorted(d for d in e["auth_domains"] if d),
            "dispositions": sorted(e["dispositions"]),
        })
    return result


def render(result):
    lines = []
    for domain, info in result["domains"].items():
        lines.append(f"{domain}   policy p={info['policy']} pct={info['pct']}"
                     f"   reporters: {', '.join(info['reporters'])}")
        if info["spoofed_messages"] and not info["policy_is_enforcing"]:
            lines.append(f"  !! {info['spoofed_messages']} message(s) failed both SPF and DKIM"
                         f" while p={info['policy']} — forged mail is being delivered")
        lines.append("")
        lines.append(f"  {'source ip':<16}{'msgs':>6}{'pass':>7}{'unalign':>9}{'spoof':>7}  class")
        for s in result["sources"]:
            lines.append(f"  {s['ip']:<16}{s['messages']:>6}{s['pass_pct']:>6}%"
                         f"{s['unaligned_pct']:>8}%{s['spoof_pct']:>6}%  {s['class']}")
            if s["class"] == "SPOOF":
                froms = ", ".join(s["header_from"][:3]) or "?"
                lines.append(f"      From: {froms}   dispositions: {', '.join(s['dispositions']) or '-'}")
            elif s["class"] == "MIXED":
                lines.append(f"      auth domains: {', '.join(s['auth_domains'][:4]) or '-'}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    reports = [parse_report(load_xml(p)) for p in args.files]
    result = analyse(reports)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))

    spoof_under_none = any(
        d["spoofed_messages"] and not d["policy_is_enforcing"]
        for d in result["domains"].values()
    )
    return 1 if spoof_under_none else 0


if __name__ == "__main__":
    sys.exit(main())
