#!/usr/bin/env bash
# Re-record backend/tests/fixtures/demo-analysis from the analyzer images.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/generate_demo_pcap.py
F=backend/tests/fixtures/demo-analysis
docker compose build analyzer-zeek analyzer-suricata
rm -rf "$F/zeek" "$F/suricata" && mkdir -p "$F/zeek" "$F/suricata" && chmod 777 "$F/zeek" "$F/suricata"
docker run --rm --network none --entrypoint zeek -v "$ROOT/demo/generated:/in:ro" -v "$ROOT/$F/zeek:/out" -w /out \
  breachreplay/analyzer-zeek:latest -C -D -r /in/breachreplay-demo.pcap LogAscii::use_json=T /opt/breachreplay/zeek/breachreplay.zeek
docker run --rm --network none --entrypoint suricata -v "$ROOT/demo/generated:/in:ro" -v "$ROOT/$F/suricata:/out" \
  breachreplay/analyzer-suricata:latest -r /in/breachreplay-demo.pcap -l /out -k none --runmode single -S /opt/breachreplay/rules/breachreplay-demo.rules >/dev/null
rm -f "$F/zeek/packet_filter.log" "$F/suricata/"{stats.log,suricata.log,fast.log}
chmod 755 "$F/zeek" "$F/suricata"
echo "fixtures recorded in $F"
