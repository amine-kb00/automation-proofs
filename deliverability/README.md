# Deliverability gate — SPF / DKIM / DMARC

Second proof artifact for the same job post: Boston's 72-hour Tracking Fix Sprint
lists *"Klaviyo health checks — abandoned checkout, browse, post-purchase, winback,
plus SPF/DKIM/DMARC"*. Flow screenshots are easy to fake. DNS state is not.

This is a check that can **fail**, run for real, against real domains.

## What it does

`check_domain.py` audits one or more domains and returns a verdict per layer:

- **SPF** — finds the record, walks the include tree, and counts DNS lookups the
  way RFC 7208 §4.6.4 does. Above **10 lookups** every message fails SPF with
  `permerror` — the classic silent killer when a store stacks Klaviyo + Shopify +
  Google Workspace + a helpdesk. Also flags `~all` vs `-all`, multiple records,
  and includes that resolve to nothing.
- **DKIM** — probes 18 common selectors, reports key size, and distinguishes three
  very different situations: a usable key, a **revoked** key (`v=DKIM1; p=` — the
  wildcard revocation trick), and *no key on the common selectors*, which is not
  proof of failure because Klaviyo and Shopify often publish a custom selector.
- **DMARC** — parses the policy, `pct`, `rua`. `p=none` is reported as a warning,
  not a pass: a monitor-only policy still delivers spoofed mail.
- **MX** — a domain with no MX cannot receive bounces, so every hard bounce is lost.

Long TXT records arrive as several quoted strings and are rejoined before parsing
(that is why `amazon.com`'s DMARC reads `p=quarantine` here and `p=` everywhere else).

## Two ways to use it

**CLI**, no account, no API key:

```bash
python3 check_domain.py shopify.com github.com
python3 check_domain.py mystore.com --selectors kl,shopify --json
```

Exit code is `0` on PASS/WARN and `1` on FAIL, so it can gate a pipeline. WARN alone
never blocks — half the internet soft-fails SPF, and a gate that cries wolf gets
switched off.

**n8n workflow** (`workflow.json`, `POST /webhook/audit-domain`):

```
Domain webhook → Validate domain → Run audit → Shape verdict → Respond
```

The domain is validated against a DNS-label regex **before** it reaches a shell, and
the workflow answers with `{ok, summary[], reports[]}` — `ok:false` plus the failing
layers is exactly what a scheduler needs to open a ticket.

## Evidence

`proof_run.txt` — live CLI run:

```
github.com   →  WARN
  SPF    WARN   10/10 DNS lookups, all=~all
         - 10 DNS lookups — dangerously close to the 10 ceiling
         - '~all' soft-fails; only '-all' refuses unauthorised senders
  DKIM   PASS   selectors: google(~2352b), k1(~1296b), k2(~2352b), s1(~2352b)…
  DMARC  PASS   p=quarantine
```

`proof_fail.txt` — `example.com`, a domain that publishes a deliberate wildcard
revocation: DKIM FAIL, exit 1.

`proof_api.txt` — the n8n webhook, 8/8 assertions:

```
  [PASS] shopify.com    ok=True    verdict=WARN   warnings: ['SPF']
  [PASS] example.com    ok=False   verdict=FAIL   blocked on: ['DKIM']
GATE PROVEN
```

## Honest limits

- `~2352b` is a base64-length estimate, not a parsed key. It is enough to catch a
  512-bit key; it is not a cryptographic measurement.
- A custom DKIM selector is invisible until the client gives it to you — the tool
  says so instead of pretending the domain is broken.
- No DMARC aggregate-report parsing (that is the next step: `rua` inbox → per-IP
  pass/fail table, which is how you learn *who* is spoofing the domain).
- The `Run audit` node needs `NODES_EXCLUDE=` (n8n 2.x ships Execute Command disabled).
  In a client deployment the same JSON comes from an HTTP node pointing at the audit
  service instead — the workflow shape does not change.


---

# DMARC aggregate reports (`dmarc_report.py`)

Everything above is what the domain *declares*. An aggregate report is what actually
*happened*: every receiver that honours `rua=` mails you an XML summary of who sent
mail as your domain, from which IP, and whether it authenticated.

    python3 dmarc_report.py fixtures/google_mystore.xml fixtures/microsoft_mystore.xml.gz

Reads plain or `.gz` (Google, Microsoft and Yahoo all gzip), tolerates the namespace
mess (Google sends none, Microsoft sends `urn:ietf:params:xml:ns:dmarc-2.0`), and
splits sources into the three populations people always confuse:

- **PASS** — aligned SPF or DKIM: a legitimate sender.
- **UNALIGN** — authenticated, but as *another* domain. A forwarder, a mailing list,
  an ESP signing with its own key. Harmless, and the reason DMARC checks alignment
  and not raw SPF.
- **SPOOF** — both failed, your domain still in `From:`. That is either forgery or a
  sender you forgot to authorise.

`proof_dmarc.txt`:

```
mystore.com   policy p=none pct=100   reporters: google.com, microsoft.com
  !! 98 message(s) failed both SPF and DKIM while p=none — forged mail is being delivered

  source ip         msgs   pass  unalign  spoof  class
  198.51.100.24      507   100%       0%     0%  PASS
  45.155.205.233      98     0%       0%   100%  SPOOF
      From: mystore.com   dispositions: none
  203.0.113.7         18     0%     100%     0%  UNALIGN
      auth domains: forwarder.example
  192.0.2.55           7   100%       0%     0%  PASS
```

Exit code 1: spoofed mail exists *and* the policy is `p=none`, so receivers are
still told to deliver it. That is the exact sentence a merchant needs to hear
before "we get spam complaints and our invoices go to junk".

**Honesty note:** the two fixtures are synthetic — they reproduce the real schema
(namespaces, `<policy_evaluated>`, gzip) but the IPs are documentation ranges
(198.51.100.0/24, 203.0.113.0/24). A live run needs the client's `rua=` mailbox.

## The full Klaviyo/ESP health check, as it stands

1. `check_domain.py` — are the records correct and within the SPF lookup ceiling?
2. `dmarc_report.py` — who is actually sending, and is anyone forging?
3. n8n workflow — the two become a verdict `{ok: false, failures: [...]}` a scheduler
   can open a ticket on.
