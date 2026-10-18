#!/usr/bin/env bash
# Convert the Playwright demo recording into README-friendly assets.
#   cd frontend && RECORD_DEMO=1 npx playwright test e2e/record-demo.spec.ts && cd .. && scripts/make_demo_gif.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:-$(find "$ROOT/frontend/test-results" -path '*record-demo*' -name 'video.webm' | head -1)}"
[ -f "$SRC" ] || { echo "no recording found; run the record-demo spec first" >&2; exit 1; }
OUT="$ROOT/docs/demo"
mkdir -p "$OUT"
ffmpeg -y -loglevel error -i "$SRC" -c:v libx264 -pix_fmt yuv420p -crf 26 -preset slow -movflags +faststart "$OUT/breachreplay-demo.mp4"
ffmpeg -y -loglevel error -i "$SRC" -vf "fps=8,scale=880:-1:flags=lanczos,palettegen=max_colors=96:stats_mode=diff" "$OUT/.palette.png"
ffmpeg -y -loglevel error -i "$SRC" -i "$OUT/.palette.png" -lavfi "fps=8,scale=880:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" "$OUT/breachreplay-demo.gif"
rm -f "$OUT/.palette.png"
ls -lh "$OUT"
