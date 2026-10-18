# Demo assets

- `breachreplay-demo.gif` / `breachreplay-demo.mp4`: about 40 s recording of the recruiter flow (landing → Watch demo → live analysis → replay → investigate WS-03 → Stop the breach → simulated containment → comparison).

Recorded from the production build (nginx + FastAPI + analyzer containers) with Playwright:

```bash
make demo
cd frontend && RECORD_DEMO=1 npx playwright test e2e/record-demo.spec.ts && cd ..
scripts/make_demo_gif.sh
```

The incident in the recording is the synthetic demo capture analyzed live by Zeek and Suricata.
