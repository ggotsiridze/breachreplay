# Recorded analyzer output (demo capture)

These files are **real output** recorded by running the project's analyzer
images against `demo/generated/breachreplay-demo.pcap` (produced by
`scripts/generate_demo_pcap.py`):

- `zeek/`: Zeek 7.0.5, `zeek -C -D -r capture.pcap LogAscii::use_json=T breachreplay.zeek`
- `suricata/eve.json`: Suricata 7.0.10, `suricata -r capture.pcap -k none --runmode single -S breachreplay-demo.rules`

They let the parser/normalization/correlation tests run without Zeek or
Suricata installed. The `analyzers`-marked integration test re-runs the real
tools when they are available. Regenerate with `make fixtures`.
