import { NextIcon, PauseIcon, PlayIcon, PrevIcon, RestartIcon, SkipBackIcon, SkipForwardIcon } from '../graph/icons';
import { SPEEDS, useApp } from '../stores/appStore';
import { type ReplayFrame, type Timeline, formatClock, formatOffset, nextEventAt, previousEventAt } from './engine';

export function ReplayControls({ timeline, frame }: { timeline: Timeline; frame: ReplayFrame }) {
  const { playing, speed, setPlaying, setSpeed, setT } = useApp();
  const atEnd = frame.t >= timeline.duration - 0.01;

  const toggle = () => {
    if (!playing && atEnd) setT(0);
    setPlaying(!playing);
  };

  return (
    <div className="br-controls">
      <div className="br-controls-time" data-testid="replay-time">
        <span className="br-mono br-controls-now">{formatOffset(frame.t)}</span>
        <span className="br-controls-sep">/</span>
        <span className="br-mono">{formatOffset(timeline.duration)}</span>
        <span className="br-controls-clock br-mono" title="Capture time (UTC)">
          {formatClock(frame.clock)} UTC
        </span>
      </div>
      <div className="br-controls-buttons">
        <button type="button" className="br-icon-btn" onClick={() => { setPlaying(false); setT(0); }} aria-label="Jump to beginning" title="Jump to beginning">
          <SkipBackIcon />
        </button>
        <button
          type="button"
          className="br-icon-btn"
          aria-label="Previous event"
          title="Previous event"
          onClick={() => {
            setPlaying(false);
            setT(previousEventAt(timeline, frame.t) ?? 0);
          }}
        >
          <PrevIcon />
        </button>
        <button type="button" className={`br-play ${playing ? 'is-playing' : ''}`} onClick={toggle} aria-label={playing ? 'Pause' : 'Play'} data-testid="play-toggle">
          {playing ? <PauseIcon size={20} /> : <PlayIcon size={20} />}
        </button>
        <button
          type="button"
          className="br-icon-btn"
          aria-label="Next event"
          title="Next event"
          onClick={() => {
            setPlaying(false);
            const next = nextEventAt(timeline, frame.t);
            setT(next !== null ? next + 0.01 : timeline.duration);
          }}
        >
          <NextIcon />
        </button>
        <button type="button" className="br-icon-btn" onClick={() => { setPlaying(false); setT(timeline.duration); }} aria-label="Jump to end" title="Jump to end">
          <SkipForwardIcon />
        </button>
        <button type="button" className="br-icon-btn" onClick={() => { setT(0); setPlaying(true); }} aria-label="Restart replay" title="Restart">
          <RestartIcon />
        </button>
      </div>
      <div className="br-controls-speed" role="group" aria-label="Replay speed">
        {SPEEDS.map((s) => (
          <button key={s} type="button" className={`br-speed ${speed === s ? 'is-on' : ''}`} onClick={() => setSpeed(s)} aria-pressed={speed === s}>
            {s}x
          </button>
        ))}
        <span className="br-speed-badge" data-testid="speed-badge">
          {speed}x REPLAY
        </span>
      </div>
    </div>
  );
}
