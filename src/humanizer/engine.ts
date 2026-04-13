/**
 * Playwright-backed humanizer engine.
 *
 * Replaces the former CDP-based engine. Uses the cloakbrowser-launched
 * Playwright Page for each target. cloakbrowser's `humanize: true` already
 * patches input dispatch at the C++ layer; this engine layers custom per-call
 * timing profiles (WPM + bigram + typo, Bezier paths, eased scroll) on top.
 *
 * humanizer_click supports locator-first targeting (selector | role+name |
 * text | label) so callers no longer need to guess pixel coordinates — the
 * locator auto-waits for visible+enabled+stable+in-view before dispatching.
 */

import type { Page, Locator } from "playwright-core";
import { getPageForTarget } from "../browser/session.js";
import { generatePath, addRandomOffset, type Point } from "./path.js";
import { calculateKeyDelays, calculateScrollSteps, type TypingProfile } from "./timing.js";

// ── Helpers ──────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

function isUpperCase(ch: string): boolean {
  return ch !== ch.toLowerCase() && ch === ch.toUpperCase();
}

// ── Mouse position tracking ──────────────────────────────────────────

interface MouseState {
  x: number;
  y: number;
}

const mouseStates = new Map<string, MouseState>();

function getMouseState(targetId: string): MouseState {
  let state = mouseStates.get(targetId);
  if (!state) {
    state = { x: 0, y: 0 };
    mouseStates.set(targetId, state);
  }
  return state;
}

function clearMouseState(targetId: string): void {
  mouseStates.delete(targetId);
}

// ── Locator resolution ───────────────────────────────────────────────

export interface ClickTarget {
  selector?: string;
  role?: string;
  name?: string;
  text?: string;
  label?: string;
  x?: number;
  y?: number;
}

function resolveLocator(page: Page, opts: ClickTarget): Locator | null {
  if (opts.selector) return page.locator(opts.selector);
  if (opts.role) {
    // Playwright requires role to be a known AriaRole; we accept any string.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return page.getByRole(opts.role as any, opts.name ? { name: opts.name } : undefined);
  }
  if (opts.text) return page.getByText(opts.text);
  if (opts.label) return page.getByLabel(opts.label);
  return null;
}

async function resolveCenter(locator: Locator): Promise<{ center: Point; box: { width: number; height: number } }> {
  await locator.waitFor({ state: "visible", timeout: 15_000 });
  await locator.scrollIntoViewIfNeeded({ timeout: 5_000 }).catch(() => { /* non-fatal */ });
  const box = await locator.boundingBox({ timeout: 5_000 });
  if (!box) {
    throw new Error("Locator has no bounding box (element not rendered or zero-size).");
  }
  return {
    center: { x: box.x + box.width / 2, y: box.y + box.height / 2 },
    box: { width: box.width, height: box.height },
  };
}

// ── Engine ───────────────────────────────────────────────────────────

class HumanizerEngine {
  /** Drop tracked mouse state when a target is closed. */
  closeSession(targetId: string): void {
    clearMouseState(targetId);
  }

  // ── Mouse movement ─────────────────────────────────────────────

  async moveMouse(
    targetId: string,
    x: number,
    y: number,
    durationMs?: number,
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const page = getPageForTarget(targetId);
    const state = getMouseState(targetId);
    const from: Point = { x: state.x, y: state.y };
    const to: Point = { x, y };

    const path = generatePath(from, to, { baseDurationMs: durationMs ?? 600 });

    let eventsDispatched = 0;
    for (let i = 0; i < path.points.length; i++) {
      const pt = path.points[i];
      if (i > 0) {
        const delay = path.timestamps[i] - path.timestamps[i - 1];
        if (delay > 0) await sleep(delay);
      }
      await page.mouse.move(pt.x, pt.y);
      eventsDispatched++;
    }

    const last = path.points[path.points.length - 1];
    state.x = last.x;
    state.y = last.y;

    return { totalMs: path.totalMs, eventsDispatched };
  }

  // ── Click ──────────────────────────────────────────────────────

  async click(
    targetId: string,
    opts: ClickTarget & {
      button?: "left" | "right" | "middle";
      clickCount?: number;
      moveDurationMs?: number;
    } = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; clickedAt: Point; resolvedBy: string }> {
    const page = getPageForTarget(targetId);
    const button = opts.button ?? "left";
    const clickCount = opts.clickCount ?? 1;

    let targetX: number;
    let targetY: number;
    let resolvedBy: string;

    const locator = resolveLocator(page, opts);
    if (locator) {
      const { center, box } = await resolveCenter(locator);
      const offset = addRandomOffset(center, box);
      targetX = offset.x;
      targetY = offset.y;
      resolvedBy = opts.selector ? "selector"
        : opts.role ? "role"
        : opts.text ? "text"
        : "label";
    } else if (opts.x !== undefined && opts.y !== undefined) {
      targetX = opts.x;
      targetY = opts.y;
      resolvedBy = "coords";
    } else {
      throw new Error("Provide one of: selector, role (+ name), text, label, or x+y coordinates.");
    }

    const moveResult = await this.moveMouse(targetId, targetX, targetY, opts.moveDurationMs);
    let eventsDispatched = moveResult.eventsDispatched;
    let totalMs = moveResult.totalMs;

    const preClickDelay = Math.round(rand(30, 80));
    await sleep(preClickDelay);
    totalMs += preClickDelay;

    for (let c = 0; c < clickCount; c++) {
      await page.mouse.down({ button });
      eventsDispatched++;

      const holdMs = Math.round(rand(40, 100));
      await sleep(holdMs);
      totalMs += holdMs;

      await page.mouse.up({ button });
      eventsDispatched++;

      if (c < clickCount - 1) {
        const interClickMs = Math.round(rand(50, 120));
        await sleep(interClickMs);
        totalMs += interClickMs;
      }
    }

    return { totalMs, eventsDispatched, clickedAt: { x: targetX, y: targetY }, resolvedBy };
  }

  // ── Typing ─────────────────────────────────────────────────────

  async typeText(
    targetId: string,
    text: string,
    profile: TypingProfile = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; charsTyped: number }> {
    const page = getPageForTarget(targetId);
    const keyDelays = calculateKeyDelays(text, profile);

    let totalMs = 0;
    let eventsDispatched = 0;

    for (const { key, delayMs } of keyDelays) {
      await sleep(delayMs);
      totalMs += delayMs;

      if (key === "Backspace") {
        await page.keyboard.press("Backspace");
        eventsDispatched++;
      } else if (key === " ") {
        await page.keyboard.press("Space");
        eventsDispatched++;
      } else if (key.length === 1) {
        // Shift is handled automatically by Playwright's keyboard.type for single chars.
        if (isUpperCase(key)) {
          await page.keyboard.press(`Shift+${key.toLowerCase()}`);
        } else {
          await page.keyboard.press(key);
        }
        eventsDispatched++;
      } else {
        // Named key (Tab, Enter, etc.)
        await page.keyboard.press(key);
        eventsDispatched++;
      }

      const holdMs = Math.round(rand(20, 60));
      await sleep(holdMs);
      totalMs += holdMs;
    }

    return { totalMs, eventsDispatched, charsTyped: text.length };
  }

  // ── Scroll ─────────────────────────────────────────────────────

  async scroll(
    targetId: string,
    deltaY: number,
    deltaX?: number,
    durationMs?: number,
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const page = getPageForTarget(targetId);
    const steps = calculateScrollSteps({ deltaY, deltaX, durationMs: durationMs ?? 400 });

    let totalMs = 0;
    let eventsDispatched = 0;

    for (const step of steps) {
      await sleep(step.delayMs);
      totalMs += step.delayMs;

      await page.mouse.wheel(step.deltaX, step.deltaY);
      eventsDispatched++;
    }

    return { totalMs, eventsDispatched };
  }

  // ── Idle simulation ────────────────────────────────────────────

  async idle(
    targetId: string,
    durationMs: number,
    intensity: "subtle" | "normal" = "subtle",
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const page = getPageForTarget(targetId);
    const state = getMouseState(targetId);
    const start = Date.now();
    let eventsDispatched = 0;

    const jitterRadius = intensity === "subtle" ? 3 : 8;
    const scrollChance = intensity === "subtle" ? 0.05 : 0.15;
    const actionInterval = intensity === "subtle" ? rand(400, 1200) : rand(200, 600);

    let elapsed = 0;
    while (elapsed < durationMs) {
      const waitMs = Math.min(
        Math.round(rand(actionInterval * 0.7, actionInterval * 1.3)),
        durationMs - elapsed,
      );
      await sleep(waitMs);
      elapsed = Date.now() - start;
      if (elapsed >= durationMs) break;

      if (Math.random() < scrollChance) {
        const microDelta = Math.round(rand(-20, 20));
        if (microDelta !== 0) {
          await page.mouse.wheel(0, microDelta);
          eventsDispatched++;
        }
      } else {
        const jx = Math.round(state.x + rand(-jitterRadius, jitterRadius));
        const jy = Math.round(state.y + rand(-jitterRadius, jitterRadius));
        await page.mouse.move(jx, jy);
        state.x = jx;
        state.y = jy;
        eventsDispatched++;
      }
    }

    return { totalMs: Date.now() - start, eventsDispatched };
  }
}

export const humanizerEngine = new HumanizerEngine();
