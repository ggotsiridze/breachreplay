export interface Point {
  x: number;
  y: number;
}

export interface Curve {
  start: Point;
  c1: Point;
  c2: Point;
  end: Point;
}

export const NODE_W = 184;
export const NODE_H = 76;

/** Point where a ray from the rectangle centre towards `toward` leaves the rectangle. */
export function boundaryPoint(center: Point, toward: Point, halfW: number, halfH: number): Point {
  const dx = toward.x - center.x;
  const dy = toward.y - center.y;
  if (dx === 0 && dy === 0) return center;
  const scale = 1 / Math.max(Math.abs(dx) / halfW, Math.abs(dy) / halfH);
  return { x: center.x + dx * scale, y: center.y + dy * scale };
}

/**
 * Edge geometry between two node centres. Backward edges (pointing left on
 * roughly the same row) arc above the graph so they never overlap the
 * forward attack path.
 */
export function edgeCurve(s: Point, t: Point, lane = 0): Curve {
  const dx = t.x - s.x;
  const dy = t.y - s.y;
  const hw = NODE_W / 2 + 4;
  const hh = NODE_H / 2 + 4;
  let c1: Point;
  let c2: Point;
  if (dx < -40 && Math.abs(dy) < 80) {
    const lift = 150 + 46 * lane;
    const top = Math.min(s.y, t.y) - lift;
    c1 = { x: s.x - 30, y: top };
    c2 = { x: t.x + 30, y: top };
    const start = { x: s.x - 18, y: s.y - hh };
    const end = { x: t.x + 18, y: t.y - hh };
    return { start, c1, c2, end };
  }
  if (Math.abs(dx) >= Math.abs(dy) * 0.6) {
    const k = Math.max(60, Math.abs(dx) * 0.45);
    c1 = { x: s.x + Math.sign(dx || 1) * k, y: s.y + lane * 10 };
    c2 = { x: t.x - Math.sign(dx || 1) * k, y: t.y - lane * 10 };
  } else {
    const k = Math.max(50, Math.abs(dy) * 0.45);
    c1 = { x: s.x + dx * 0.15, y: s.y + Math.sign(dy) * k };
    c2 = { x: t.x - dx * 0.15, y: t.y - Math.sign(dy) * k };
  }
  return { start: boundaryPoint(s, c1, hw, hh), c1, c2, end: boundaryPoint(t, c2, hw, hh) };
}

export function curvePath(c: Curve): string {
  return `M ${c.start.x},${c.start.y} C ${c.c1.x},${c.c1.y} ${c.c2.x},${c.c2.y} ${c.end.x},${c.end.y}`;
}

export function pointAt(c: Curve, u: number): Point {
  const v = 1 - u;
  const a = v * v * v;
  const b = 3 * v * v * u;
  const d = 3 * v * u * u;
  const e = u * u * u;
  return {
    x: a * c.start.x + b * c.c1.x + d * c.c2.x + e * c.end.x,
    y: a * c.start.y + b * c.c1.y + d * c.c2.y + e * c.end.y,
  };
}

export function tangentAngle(c: Curve, u: number): number {
  const p1 = pointAt(c, Math.max(0, u - 0.01));
  const p2 = pointAt(c, Math.min(1, u + 0.01));
  return (Math.atan2(p2.y - p1.y, p2.x - p1.x) * 180) / Math.PI;
}

/** Split a cubic Bézier at parameter u (de Casteljau). */
export function splitCurve(c: Curve, u: number): [Curve, Curve] {
  const lerp = (a: Point, b: Point): Point => ({ x: a.x + (b.x - a.x) * u, y: a.y + (b.y - a.y) * u });
  const p01 = lerp(c.start, c.c1);
  const p12 = lerp(c.c1, c.c2);
  const p23 = lerp(c.c2, c.end);
  const p012 = lerp(p01, p12);
  const p123 = lerp(p12, p23);
  const mid = lerp(p012, p123);
  return [
    { start: c.start, c1: p01, c2: p012, end: mid },
    { start: mid, c1: p123, c2: p23, end: c.end },
  ];
}
