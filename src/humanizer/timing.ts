/**
 * Typing & scroll timing models for human-like input simulation.
 *
 * Provides keystroke delay calculation with bigram frequency modifiers,
 * typo simulation with QWERTY neighbor mapping, and scroll velocity
 * distribution with easeInOutQuad profiles.
 */

// ── Typing models ────────────────────────────────────────────────────

export interface TypingProfile {
  /** Words per minute (default: 40). */
  wpm?: number;
  /** Probability of a typo per character, 0-1 (default: 0). */
  errorRate?: number;
}

export interface KeyDelay {
  /** The key to press (single char or special like "Backspace"). */
  key: string;
  /** Delay in ms before pressing this key. */
  delayMs: number;
}

/** Top 30 English bigrams — typed faster due to muscle memory. */
const FAST_BIGRAMS = new Set([
  "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
  "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
  "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
]);

/** QWERTY neighbor-key map for realistic typo targets. */
const QWERTY_NEIGHBORS: Record<string, string[]> = {
  q: ["w", "a"],
  w: ["q", "e", "a", "s"],
  e: ["w", "r", "s", "d"],
  r: ["e", "t", "d", "f"],
  t: ["r", "y", "f", "g"],
  y: ["t", "u", "g", "h"],
  u: ["y", "i", "h", "j"],
  i: ["u", "o", "j", "k"],
  o: ["i", "p", "k", "l"],
  p: ["o", "l"],
  a: ["q", "w", "s", "z"],
  s: ["a", "w", "e", "d", "z", "x"],
  d: ["s", "e", "r", "f", "x", "c"],
  f: ["d", "r", "t", "g", "c", "v"],
  g: ["f", "t", "y", "h", "v", "b"],
  h: ["g", "y", "u", "j", "b", "n"],
  j: ["h", "u", "i", "k", "n", "m"],
  k: ["j", "i", "o", "l", "m"],
  l: ["k", "o", "p"],
  z: ["a", "s", "x"],
  x: ["z", "s", "d", "c"],
  c: ["x", "d", "f", "v"],
  v: ["c", "f", "g", "b"],
  b: ["v", "g", "h", "n"],
  n: ["b", "h", "j", "m"],
  m: ["n", "j", "k"],
};

function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

function jitter(base: number): number {
  return base * rand(0.85, 1.15);
}

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function isUpperCase(ch: string): boolean {
  return ch !== ch.toLowerCase() && ch === ch.toUpperCase();
}

/**
 * Calculate keystroke delays for a text string with human-like timing.
 *
 * Models:
 * - Base delay from WPM (assuming 5 chars per word)
 * - Bigram frequency modifier: common bigrams → 0.8x delay
 * - Shift penalty: uppercase letters → +50ms
 * - Word boundary pause: spaces → +20-60ms
 * - Random jitter: ±15% on each delay
 * - Optional typo injection with backspace correction
 */
export function calculateKeyDelays(text: string, profile: TypingProfile = {}): KeyDelay[] {
  const wpm = profile.wpm ?? 40;
  const errorRate = Math.max(0, Math.min(1, profile.errorRate ?? 0));

  // Base delay: WPM → ms per character (5 chars per word)
  const baseDelayMs = (60_000 / wpm) / 5;

  const result: KeyDelay[] = [];
  let prevChar = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    let delay = baseDelayMs;

    // Bigram modifier
    const bigram = (prevChar + ch).toLowerCase();
    if (bigram.length === 2 && FAST_BIGRAMS.has(bigram)) {
      delay *= 0.8;
    }

    // Shift penalty for uppercase
    if (isUpperCase(ch)) {
      delay += 50;
    }

    // Word boundary pause
    if (ch === " ") {
      delay += rand(20, 60);
    }

    // Apply jitter
    delay = jitter(delay);

    // Typo simulation
    if (errorRate > 0 && Math.random() < errorRate) {
      const lower = ch.toLowerCase();
      const neighbors = QWERTY_NEIGHBORS[lower];
      if (neighbors && neighbors.length > 0) {
        // Type wrong key
        let wrongKey = pickRandom(neighbors);
        if (isUpperCase(ch)) wrongKey = wrongKey.toUpperCase();
        result.push({ key: wrongKey, delayMs: Math.round(delay) });

        // Pause before noticing the error
        result.push({ key: "Backspace", delayMs: Math.round(rand(80, 200)) });

        // Retype correct key with slight hesitation
        result.push({ key: ch, delayMs: Math.round(rand(50, 120)) });

        prevChar = ch;
        continue;
      }
    }

    result.push({ key: ch, delayMs: Math.round(delay) });
    prevChar = ch;
  }

  return result;
}

// ── Scroll models ────────────────────────────────────────────────────

export interface ScrollOptions {
  /** Total vertical scroll delta in pixels. */
  deltaY: number;
  /** Total horizontal scroll delta in pixels (default: 0). */
  deltaX?: number;
  /** Total scroll duration in ms (default: 400). */
  durationMs?: number;
  /** Time step in ms between scroll events (default: 16 ~= 60Hz). */
  stepMs?: number;
}

export interface ScrollStep {
  /** Vertical delta for this step. */
  deltaY: number;
  /** Horizontal delta for this step. */
  deltaX: number;
  /** Delay in ms before dispatching this step. */
  delayMs: number;
}

function easeInOutQuad(t: number): number {
  return t < 0.5
    ? 2 * t * t
    : 1 - Math.pow(-2 * t + 2, 2) / 2;
}

/**
 * Calculate scroll steps with natural acceleration/deceleration.
 *
 * Uses easeInOutQuad velocity distribution across steps.
 * Rounds deltas to integers with sum correction to ensure
 * total scroll matches the requested amount exactly.
 */
export function calculateScrollSteps(opts: ScrollOptions): ScrollStep[] {
  const totalDy = opts.deltaY;
  const totalDx = opts.deltaX ?? 0;
  const durationMs = opts.durationMs ?? 400;
  const stepMs = opts.stepMs ?? 16;

  const steps = Math.max(1, Math.ceil(durationMs / stepMs));

  // Calculate velocity weights via eased positions
  const easedPositions: number[] = [];
  for (let i = 0; i <= steps; i++) {
    easedPositions.push(easeInOutQuad(i / steps));
  }

  // Deltas between consecutive eased positions (velocity-proportional)
  const rawWeights: number[] = [];
  for (let i = 0; i < steps; i++) {
    rawWeights.push(easedPositions[i + 1] - easedPositions[i]);
  }

  // Distribute total delta proportionally with integer rounding
  const result: ScrollStep[] = [];
  let accDy = 0;
  let accDx = 0;
  const delayPerStep = Math.round(durationMs / steps);

  for (let i = 0; i < steps; i++) {
    const targetDy = Math.round(totalDy * easedPositions[i + 1]);
    const targetDx = Math.round(totalDx * easedPositions[i + 1]);

    const dy = targetDy - accDy;
    const dx = targetDx - accDx;
    accDy = targetDy;
    accDx = targetDx;

    // Skip zero-delta steps (except first and last)
    if (dy === 0 && dx === 0 && i > 0 && i < steps - 1) continue;

    result.push({
      deltaY: dy,
      deltaX: dx,
      delayMs: delayPerStep,
    });
  }

  return result;
}
