/**
 * Bezier curve mouse path generation for human-like mouse movement.
 *
 * Generates curved paths with randomized control points, Fitts's law velocity
 * scaling, and optional overshoot+correction for long distances.
 */

export interface Point {
  x: number;
  y: number;
}

export interface PathOptions {
  /** Target width in pixels for Fitts's law (default: 20). */
  targetWidth?: number;
  /** Base duration in ms before Fitts scaling (default: 600). */
  baseDurationMs?: number;
  /** Enable overshoot+correction for distances > 200px (default: true). */
  overshoot?: boolean;
  /** Time step in ms between path points (default: 8 ~= 120Hz). */
  stepMs?: number;
}

export interface PathResult {
  points: Point[];
  totalMs: number;
  timestamps: number[];
}

// ── Math helpers ─────────────────────────────────────────────────────

function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

function distance(a: Point, b: Point): number {
  return Math.hypot(b.x - a.x, b.y - a.y);
}

function easeInOutCubic(t: number): number {
  return t < 0.5
    ? 4 * t * t * t
    : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

/** Cubic Bezier interpolation at parameter t ∈ [0,1]. */
function cubicBezier(p0: Point, p1: Point, p2: Point, p3: Point, t: number): Point {
  const u = 1 - t;
  const uu = u * u;
  const uuu = uu * u;
  const tt = t * t;
  const ttt = tt * t;
  return {
    x: uuu * p0.x + 3 * uu * t * p1.x + 3 * u * tt * p2.x + ttt * p3.x,
    y: uuu * p0.y + 3 * uu * t * p1.y + 3 * u * tt * p2.y + ttt * p3.y,
  };
}

/**
 * Build randomized control points for a cubic Bezier between `from` and `to`.
 * Both control points are placed on the same side of the direct path to
 * produce a natural arc (no S-curves).
 */
function randomControlPoints(from: Point, to: Point): [Point, Point] {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const dist = Math.hypot(dx, dy) || 1;

  // Perpendicular direction
  const px = -dy / dist;
  const py = dx / dist;

  // Same side: both offsets share the same sign
  const side = Math.random() < 0.5 ? 1 : -1;
  const spread1 = rand(0.15, 0.45) * dist * side;
  const spread2 = rand(0.15, 0.45) * dist * side;

  const cp1: Point = {
    x: from.x + dx * rand(0.2, 0.4) + px * spread1,
    y: from.y + dy * rand(0.2, 0.4) + py * spread1,
  };

  const cp2: Point = {
    x: from.x + dx * rand(0.6, 0.8) + px * spread2,
    y: from.y + dy * rand(0.6, 0.8) + py * spread2,
  };

  return [cp1, cp2];
}

/**
 * Fitts's law duration scaling:  totalDuration *= log2(distance / targetWidth + 1)
 */
function fittsDuration(dist: number, targetWidth: number, baseDuration: number): number {
  if (dist < 1) return baseDuration * 0.1;
  return baseDuration * Math.log2(dist / targetWidth + 1);
}

/**
 * Discretize a Bezier curve to integer pixel coordinates with eased timing.
 * Deduplicates consecutive identical points.
 */
function discretizePath(
  from: Point,
  cp1: Point,
  cp2: Point,
  to: Point,
  totalMs: number,
  stepMs: number,
): { points: Point[]; timestamps: number[] } {
  const steps = Math.max(1, Math.ceil(totalMs / stepMs));
  const points: Point[] = [];
  const timestamps: number[] = [];

  let lastX = -Infinity;
  let lastY = -Infinity;

  for (let i = 0; i <= steps; i++) {
    const linearT = i / steps;
    const easedT = easeInOutCubic(linearT);
    const pt = cubicBezier(from, cp1, cp2, to, easedT);

    const ix = Math.round(pt.x);
    const iy = Math.round(pt.y);

    // Deduplicate consecutive identical points
    if (ix === lastX && iy === lastY) continue;
    lastX = ix;
    lastY = iy;

    points.push({ x: ix, y: iy });
    timestamps.push(Math.round(linearT * totalMs));
  }

  // Ensure final point is exact destination
  const last = points[points.length - 1];
  const destX = Math.round(to.x);
  const destY = Math.round(to.y);
  if (!last || last.x !== destX || last.y !== destY) {
    points.push({ x: destX, y: destY });
    timestamps.push(Math.round(totalMs));
  }

  return { points, timestamps };
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Generate a human-like mouse path from `from` to `to`.
 *
 * Uses cubic Bezier curves with randomized control points and eased timing.
 * For long distances (>200px), adds an overshoot-and-correct sub-path.
 */
export function generatePath(from: Point, to: Point, opts: PathOptions = {}): PathResult {
  const targetWidth = opts.targetWidth ?? 20;
  const baseDurationMs = opts.baseDurationMs ?? 600;
  const enableOvershoot = opts.overshoot ?? true;
  const stepMs = opts.stepMs ?? 8;

  const dist = distance(from, to);

  // For very short distances, just return start → end
  if (dist < 2) {
    return {
      points: [{ x: Math.round(from.x), y: Math.round(from.y) }, { x: Math.round(to.x), y: Math.round(to.y) }],
      totalMs: Math.round(baseDurationMs * 0.1),
      timestamps: [0, Math.round(baseDurationMs * 0.1)],
    };
  }

  // Main curve
  const totalMs = Math.round(fittsDuration(dist, targetWidth, baseDurationMs));
  const [cp1, cp2] = randomControlPoints(from, to);

  if (!enableOvershoot || dist <= 200) {
    const { points, timestamps } = discretizePath(from, cp1, cp2, to, totalMs, stepMs);
    return { points, totalMs, timestamps };
  }

  // Overshoot: go past target by 5-15px, then correct
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const overshootDist = rand(5, 15);
  const angle = Math.atan2(dy, dx) + rand(-0.2, 0.2);
  const overshootPt: Point = {
    x: to.x + Math.cos(angle) * overshootDist,
    y: to.y + Math.sin(angle) * overshootDist,
  };

  // Phase 1: from → overshoot (80% of time)
  const phase1Ms = Math.round(totalMs * 0.8);
  const phase1 = discretizePath(from, cp1, cp2, overshootPt, phase1Ms, stepMs);

  // Phase 2: overshoot → target (20% of time, small correction)
  const phase2Ms = totalMs - phase1Ms;
  const corrCp1: Point = {
    x: overshootPt.x + rand(-2, 2),
    y: overshootPt.y + rand(-2, 2),
  };
  const corrCp2: Point = {
    x: to.x + rand(-1, 1),
    y: to.y + rand(-1, 1),
  };
  const phase2 = discretizePath(overshootPt, corrCp1, corrCp2, to, phase2Ms, stepMs);

  // Concatenate, adjusting phase2 timestamps
  const points = [...phase1.points, ...phase2.points.slice(1)];
  const timestamps = [
    ...phase1.timestamps,
    ...phase2.timestamps.slice(1).map((t) => t + phase1Ms),
  ];

  return { points, totalMs, timestamps };
}

/**
 * Add a random offset to a center point, staying within bounds.
 * Used for randomizing click targets within an element's bounding box.
 */
export function addRandomOffset(
  center: Point,
  bounds: { width: number; height: number },
): Point {
  // Stay within inner 60% of the element
  const rx = rand(-0.3, 0.3) * bounds.width;
  const ry = rand(-0.3, 0.3) * bounds.height;
  return {
    x: Math.round(center.x + rx),
    y: Math.round(center.y + ry),
  };
}
