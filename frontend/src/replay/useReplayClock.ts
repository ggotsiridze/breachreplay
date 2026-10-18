import { useEffect, useRef } from 'react';

import { useApp } from '../stores/appStore';

/**
 * Advances the replay time while playing. 1x equals real elapsed time between
 * reconstructed events; other speeds scale it. Updates are throttled to ~30 Hz
 * because every visual is derived from t.
 */
export function useReplayClock(duration: number) {
  const playing = useApp((s) => s.playing);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    if (!playing) return;
    let last = performance.now();
    let acc = 0;
    const tick = (now: number) => {
      const dt = Math.min(0.25, (now - last) / 1000);
      last = now;
      acc += dt;
      if (acc >= 1 / 30) {
        const { t, speed, setT, setPlaying } = useApp.getState();
        const next = t + acc * speed;
        acc = 0;
        if (next >= duration) {
          setT(duration);
          setPlaying(false);
          return;
        }
        setT(next);
      }
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => {
      if (raf.current !== null) cancelAnimationFrame(raf.current);
    };
  }, [playing, duration]);
}
