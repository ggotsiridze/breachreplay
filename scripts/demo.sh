#!/usr/bin/env bash
# make demo: build and start the full stack, run the synthetic demo capture
# through the REAL pipeline (Zeek + Suricata + correlation), and print URLs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WEB_URL="http://localhost:${WEB_PORT:-8080}"
API_URL="http://localhost:${API_PORT:-8000}"

step() { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

step "1/7 Checking requirements"
command -v docker >/dev/null || die "Docker is required (https://docs.docker.com/get-docker/)"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"
docker info >/dev/null 2>&1 || die "The Docker daemon is not running"
command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
echo "docker $(docker version --format '{{.Server.Version}}'), $(docker compose version --short 2>/dev/null || echo compose v2), $(python3 --version)"

step "2/7 Generating the safe synthetic demo capture"
python3 scripts/generate_demo_pcap.py

step "3/7 Building and starting containers (analyzers, backend, frontend)"
docker compose up -d --build

step "4/7 Waiting for services to become healthy"
for i in $(seq 1 90); do
  if curl -fsS "$API_URL/health" >/dev/null 2>&1 && curl -fsS "$WEB_URL/healthz" >/dev/null 2>&1; then
    break
  fi
  [ "$i" = 90 ] && { docker compose ps; die "services did not become healthy"; }
  sleep 2
done
docker compose ps --format 'table {{.Service}}\t{{.Status}}'

step "5/7 Running the demo capture through Zeek + Suricata + correlation"
ID="$(curl -fsS -X POST "$API_URL/api/incidents/demo" | python3 -c 'import json,sys; print(json.load(sys.stdin)["incident_id"])')"
for i in $(seq 1 120); do
  STATUS="$(curl -fsS "$API_URL/api/incidents/$ID/status")"
  STATE="$(echo "$STATUS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')"
  [ "$STATE" = COMPLETE ] && break
  [ "$STATE" = FAILED ] && { echo "$STATUS"; die "demo analysis failed"; }
  sleep 1
done
[ "$STATE" = COMPLETE ] || die "demo analysis did not complete in time"
STATUS_FILE="$(mktemp)"
echo "$STATUS" >"$STATUS_FILE"
python3 - "$STATUS_FILE" <<'PY'
import json, sys
for s in json.load(open(sys.argv[1]))["steps"]:
    print(f"  \u2713 {s['label']:<24} {s['detail'] or ''}")
PY
rm -f "$STATUS_FILE"

step "6/7 Incident"
curl -fsS "$API_URL/api/incidents/$ID" | python3 -c '
import json, sys
inc = json.load(sys.stdin)["incident"]
print("  " + inc["summary"]["headline"])
print("  path:", " -> ".join(a.replace("asset-", "").upper() for a in inc["primary_attack_path"]))'

step "7/7 Ready"
cat <<MSG

  BreachReplay   $WEB_URL        <- open this, then click "Watch demo incident"
  API docs       $API_URL/docs
  Verify         make verify
  Stop           make down

MSG
