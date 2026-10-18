#!/usr/bin/env bash
# BreachReplay end-to-end verification against a running stack.
#
#   scripts/verify.sh                       # full mode (make demo)
#   SHOWCASE=1 scripts/verify.sh            # showcase mode (make showcase)
#   WEB_URL=... API_URL=... scripts/verify.sh
#
# Every check is executed; the summary counts what actually passed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_URL="${WEB_URL:-http://localhost:8080}"
API_URL="${API_URL:-http://localhost:8000}"
SHOWCASE="${SHOWCASE:-0}"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
[ -t 1 ] || { G=""; R=""; D=""; N=""; }

check() {
  local name="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    pass=$((pass + 1)); printf '%s[PASS]%s %s %s%s%s\n' "$G" "$N" "$name" "$D" "${out:+· $out}" "$N"
  else
    fail=$((fail + 1)); printf '%s[FAIL]%s %s\n       %s\n' "$R" "$N" "$name" "${out:-no output}"
  fi
}

json() { "$PY" -c "import json,sys; d=json.load(sys.stdin); $1"; }
get() { curl -fsS --max-time 20 "$1"; }

# --- Repository ---------------------------------------------------------

files_present() {
  local missing=()
  for f in README.md ARCHITECTURE.md SECURITY.md LICENSE Makefile docker-compose.yml docker-compose.showcase.yml .gitignore .env.example \
    backend/Dockerfile backend/requirements.txt frontend/Dockerfile frontend/package.json analyzer/Dockerfile.zeek analyzer/Dockerfile.suricata \
    scripts/generate_demo_pcap.py scripts/export_showcase.py demo/rules/breachreplay-demo.rules showcase/showcase-incident.json .github/workflows/ci.yml; do
    [ -e "$ROOT/$f" ] || missing+=("$f")
  done
  [ ${#missing[@]} -eq 0 ] || { echo "missing: ${missing[*]}"; return 1; }
  echo "all expected files present"
}

no_committed_captures() {
  command -v git >/dev/null || { echo "git not available"; return 0; }
  local tracked
  tracked="$(git -C "$ROOT" ls-files '*.pcap' '*.pcapng' '*.cap' 'uploads/*' 'analysis-output/*' '.env' 2>/dev/null)"
  [ -z "$tracked" ] || { echo "tracked capture/env files: $tracked"; return 1; }
  echo "no captures, uploads or .env tracked by git"
}

showcase_valid() {
  "$PY" - "$ROOT/showcase/showcase-incident.json" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
inc = d["incident"]
assert d["format"] == "breachreplay-showcase/1"
assert inc["showcase"] is True and inc["demo"] is True
assert inc["incident_found"] and inc["primary_attack_path"]
assert inc["primary_attack_path"][-1] in inc["crown_jewels"]
text = json.dumps(d)
assert not re.search(r"\b10\.20\.\d+\.\d+\b", text), "unmasked internal address in showcase export"
assert "user_agent" not in text
print(f"{len(inc['assets'])} assets, {len(inc['edges'])} edges, {len(inc['events'])} events, {len(d['evidence'])} evidence, internal IPs masked")
PY
}

check "Expected files" files_present
check "No committed captures or secrets" no_committed_captures
check "Showcase data valid and sanitized" showcase_valid

# --- Services -----------------------------------------------------------

check "Backend health" bash -c "get() { curl -fsS --max-time 10 \"\$1\"; }; get '$API_URL/health' | $PY -c 'import json,sys; assert json.load(sys.stdin)[\"status\"]==\"ok\"; print(\"ok\")'"
check "Production frontend reachable" bash -c "curl -fsS --max-time 10 '$WEB_URL/' | grep -q '<title>BreachReplay</title>' && echo 'index served by nginx'"
check "Frontend proxies the API" bash -c "curl -fsS --max-time 10 '$WEB_URL/api/status' | $PY -c 'import json,sys; d=json.load(sys.stdin); print(\"showcase\" if d[\"showcase_mode\"] else \"full mode\")'"

if [ "$SHOWCASE" != "1" ]; then
  check "Analyzers reachable from backend" bash -c "curl -fsS --max-time 10 '$API_URL/api/status' | $PY -c '
import json,sys
a=json.load(sys.stdin)[\"analyzers\"]
assert \"zeek version\" in a[\"zeek\"] and \"Suricata version\" in a[\"suricata\"], a
print(a[\"zeek\"], \"/\", a[\"suricata\"])'"
fi

# --- Demo analysis ------------------------------------------------------

start_demo() {
  curl -fsS --max-time 20 -X POST "$API_URL/api/incidents/demo" | json "print(d['incident_id'])" >"$TMP/id"
  echo "incident $(cat "$TMP/id")"
}
check "Demo incident started" start_demo
ID="$(cat "$TMP/id" 2>/dev/null || true)"

wait_complete() {
  local deadline=$((SECONDS + 120)) st
  while [ $SECONDS -lt $deadline ]; do
    st="$(get "$API_URL/api/incidents/$1/status")" || return 1
    echo "$st" >"$TMP/status"
    case "$(echo "$st" | json "print(d['state'])")" in
      COMPLETE) echo "analysis complete"; return 0 ;;
      FAILED) echo "$st" | json "print(d['error_message'], d.get('error_detail'))"; return 1 ;;
    esac
    sleep 0.5
  done
  echo "timed out"; return 1
}
check "Demo analysis completed" wait_complete "$ID"

if [ "$SHOWCASE" != "1" ]; then
  check "Zeek and Suricata produced output" bash -c "$PY - '$TMP/status' <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
steps = {s['label']: s for s in d['steps']}
for name in ('Zeek analysis', 'Suricata analysis'):
    assert steps[name]['status'] == 'done', steps[name]
    assert 'output files' in (steps[name]['detail'] or ''), steps[name]
print(steps['Zeek analysis']['detail'], '|', steps['Suricata analysis']['detail'])
PY"
  check "Evidence normalized and correlated" bash -c "$PY - '$TMP/status' <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))['stats']
assert s['evidence_records'] > 0 and s['events'] > 0 and s['detections'] > 0, s
print(f\"{s['evidence_records']} evidence records, {s['detections']} detections, {s['events']} incident events\")
PY"
fi

check "Incident summary" bash -c "curl -fsS '$API_URL/api/incidents/$ID' | $PY -c '
import json,sys
inc=json.load(sys.stdin)[\"incident\"]
assert inc[\"incident_found\"] and inc[\"summary\"][\"crown_jewel_reached\"]
print(inc[\"summary\"][\"headline\"])'"

check "Incident graph" bash -c "curl -fsS '$API_URL/api/incidents/$ID/graph' | $PY -c '
import json,sys
g=json.load(sys.stdin)
assert g[\"nodes\"] and g[\"edges\"] and g[\"primary_attack_path\"][-1] in g[\"crown_jewels\"]
print(len(g[\"nodes\"]), \"nodes,\", len(g[\"edges\"]), \"edges, path:\", \" -> \".join(p.replace(\"asset-\",\"\") for p in g[\"primary_attack_path\"]))'"

check "Events endpoint (chronological)" bash -c "curl -fsS '$API_URL/api/incidents/$ID/events' | $PY -c '
import json,sys
ev=json.load(sys.stdin)[\"events\"]
ts=[e[\"timestamp\"] for e in ev]
assert ev and ts==sorted(ts)
assert all(e[\"reasons\"] for e in ev)
print(len(ev), \"events,\", sum(1 for e in ev if e[\"technique_id\"]), \"with ATT&CK mappings\")'"

check "Timeline endpoint" bash -c "curl -fsS '$API_URL/api/incidents/$ID/timeline' | $PY -c '
import json,sys
t=json.load(sys.stdin)
o=[e[\"offset_seconds\"] for e in t[\"entries\"]]
assert o and o[0]==0 and o==sorted(o)
print(\"duration\", t[\"duration_seconds\"], \"s\")'"

check "Evidence endpoint" bash -c "
EV=\$(curl -fsS '$API_URL/api/incidents/$ID/events' | $PY -c 'import json,sys; print(json.load(sys.stdin)[\"events\"][-1][\"evidence_ids\"][0])')
curl -fsS \"$API_URL/api/incidents/$ID/evidence/\$EV\" | $PY -c 'import json,sys; d=json.load(sys.stdin); print(d[\"id\"], \"-\", d[\"summary\"][:60])'"

simulate() {
  curl -fsS -X POST "$API_URL/api/incidents/$ID/simulate" -H 'Content-Type: application/json' \
    -d '{"controls":[{"control_type":"isolate_asset","asset_id":"asset-ws-03","activation":"first_detection"}]}' >"$TMP/sim" || return 1
  json "assert d['crown_jewel_before'] and not d['crown_jewel_after'] and d['interrupted_event_id']; print('crown jewel', 'reached' if d['crown_jewel_before'] else 'not reached', '->', 'protected', '| interrupted at', d['interrupted_edge_id'])" <"$TMP/sim"
}
check "Simulation endpoint (isolate WS-03)" simulate

check "Simulation retrievable" bash -c "
SID=\$($PY -c 'import json; print(json.load(open(\"$TMP/sim\"))[\"id\"])')
curl -fsS \"$API_URL/api/incidents/$ID/simulation/\$SID\" | $PY -c 'import json,sys; print(\"simulation\", json.load(sys.stdin)[\"id\"])'"

check "Observed incident unchanged by simulation" bash -c "curl -fsS '$API_URL/api/incidents/$ID' | $PY -c '
import json,sys; assert json.load(sys.stdin)[\"incident\"][\"summary\"][\"crown_jewel_reached\"]; print(\"observed crown-jewel access still recorded\")'"

check "WebSocket progress endpoint" bash -c "curl -sS -i --max-time 3 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' '$WEB_URL/ws/incidents/$ID' 2>/dev/null | head -1 | grep -q ' 101 ' && echo 'upgrade accepted through nginx'"

if [ "$SHOWCASE" != "1" ]; then
  check "Upload validation rejects non-captures" bash -c "
printf 'not a capture' > '$TMP/fake.pcap'
code=\$(curl -s -o '$TMP/up.json' -w '%{http_code}' -F 'file=@$TMP/fake.pcap' '$WEB_URL/api/incidents/upload')
[ \"\$code\" = 400 ] && $PY -c 'import json; print(json.load(open(\"$TMP/up.json\"))[\"detail\"][\"code\"])'"

  upload_capture() {
    "$PY" "$ROOT/scripts/generate_demo_pcap.py" -o "$TMP/upload-test.pcap" >/dev/null || return 1
    curl -fsS -F "file=@$TMP/upload-test.pcap" "$WEB_URL/api/incidents/upload" | json "print(d['incident_id'])" >"$TMP/upid" || return 1
    wait_complete "$(cat "$TMP/upid")" >/dev/null || { echo "upload analysis failed"; return 1; }
    echo "uploaded capture analyzed by the real pipeline"
  }
  check "Upload pipeline (pcap through nginx)" upload_capture
else
  check "Uploads disabled in showcase" bash -c "code=\$(curl -s -o /dev/null -w '%{http_code}' -F 'file=@$ROOT/README.md' '$WEB_URL/api/incidents/upload'); [ \"\$code\" = 403 ] && echo 'HTTP 403'"
fi

total=$((pass + fail))
echo
if [ $fail -eq 0 ]; then
  printf '%s%d/%d checks passed%s\n' "$G" "$pass" "$total" "$N"
else
  printf '%s%d/%d checks passed (%d failed)%s\n' "$R" "$pass" "$total" "$fail" "$N"
  exit 1
fi
