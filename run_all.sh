#!/usr/bin/env bash
# One command, all proofs. This is the thing a client can run, and the thing a
# Loom points at — a proof that only works on my machine is an anecdote.
#
#   ./run_all.sh            # offline proofs always; webhook proofs if n8n is up
#   ./run_all.sh --strict   # exit 1 if any proof was skipped for lack of a server
set -uo pipefail
cd "$(dirname "$0")"

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

pass=0; fail=0; skip=0
ROWS=()

run_expect() {  # <name> <expected_exit> <note> <cmd...>
  local name="$1" want="$2" note="$3"; shift 3
  local out rc verdict
  out=$("$@" 2>&1); rc=$?
  if [ "$rc" -eq "$want" ]; then
    pass=$((pass+1)); verdict=PASS
  else
    fail=$((fail+1)); verdict=FAIL
    note="exit $rc, expected $want"
  fi
  ROWS+=("$(printf '%-32s %-4s %s' "$name" "$verdict" "$note")")
}

skip_proof() { skip=$((skip+1)); ROWS+=("$(printf '%-32s %-4s %s' "$1" "SKIP" "$2")"); }

# --- offline: deterministic, no server, no credentials ----------------------
# dmarc exits 1 here on purpose: 98 forged messages under p=none must fail.
run_expect "dmarc: aggregate reports"   1 "98 spoofed msgs -> p=none blocks nothing" \
  python3 deliverability/dmarc_report.py \
    deliverability/fixtures/google_mystore.xml deliverability/fixtures/microsoft_mystore.xml.gz
run_expect "klaviyo: flows (healthy)"    0 "5/5 ok" \
  python3 klaviyo-audit/audit_flows.py klaviyo-audit/fixtures/healthy.json
run_expect "klaviyo: flows (broken)"     1 "checkout in draft, 48h delay, 3 flows missing" \
  python3 klaviyo-audit/audit_flows.py klaviyo-audit/fixtures/broken.json
run_expect "klaviyo: flows (thin export)" 1 "UNSCORED must not pass" \
  python3 klaviyo-audit/audit_flows.py klaviyo-audit/fixtures/thin.json

# --- live DNS ---------------------------------------------------------------
run_expect "dns: shopify.com"            0 "SPF 4 lookups, DMARC p=reject -> WARN, allowed" \
  python3 deliverability/check_domain.py shopify.com --json
# a gate that cannot fail proves nothing: example.com has a revoked DKIM key
run_expect "dns: gate closes (example)"  1 "revoked DKIM key -> FAIL -> exit 1" \
  python3 deliverability/check_domain.py example.com

# --- webhook proofs need the n8n instance + a receiver this suite owns -----
MOCK_PORT=8799
MOCK_PID=""
cleanup() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null; }
trap cleanup EXIT

start_mock() {
  # The imported workflow posts to a fixed URL, so the harness owns that port
  # for the duration of the run. A receiver left over from an earlier session
  # writes to its own log, and the proof would then read an empty one and fail
  # for the wrong reason.
  pkill -f "mock_receiver.py" 2>/dev/null
  sleep 0.5
  rm -f shopify-tracking/receipts.jsonl
  python3 shopify-tracking/mock_receiver.py & MOCK_PID=$!
  for _ in $(seq 1 25); do
    if python3 - "$MOCK_PORT" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(0.4)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except Exception:
    raise SystemExit(1)
raise SystemExit(0)
PY
    then return 0; fi
    sleep 0.2
  done
  return 1
}

if curl -fsS -m 3 http://127.0.0.1:5678/healthz >/dev/null 2>&1; then
  if start_mock; then
    run_expect "n8n: shopify dedup"        0 "3 deliveries -> 4 events, retry emits 0" \
      python3 shopify-tracking/test_dedup.py
    run_expect "n8n: deliverability webhook" 0 "8/8 assertions" \
      python3 deliverability/test_audit_api.py
  else
    skip_proof "n8n: shopify dedup"         "mock receiver did not start on :$MOCK_PORT"
    skip_proof "n8n: deliverability webhook" "mock receiver did not start on :$MOCK_PORT"
  fi
else
  skip_proof "n8n: shopify dedup"        "n8n not listening on :5678"
  skip_proof "n8n: deliverability webhook" "n8n not listening on :5678"
fi

printf '\n=====================================================================\n'
printf '%s\n' "${ROWS[@]}"
printf '=====================================================================\n'
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"

if [ "$skip" -gt 0 ]; then
  printf '\nstart n8n for the two webhook proofs:\n'
  printf '  cd ../tools && N8N_PORT=5678 N8N_HOST=127.0.0.1 N8N_SECURE_COOKIE=false \\\n'
  printf '    N8N_USER_FOLDER=$PWD/.n8n NODES_EXCLUDE= node node_modules/n8n/bin/n8n start\n'
fi

[ "$fail" -gt 0 ] && exit 1
[ "$STRICT" -eq 1 ] && [ "$skip" -gt 0 ] && exit 1
exit 0
