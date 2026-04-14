/**
 * Humanizer engine — thin wrappers over cloakbrowser-patched Playwright.
 *
 * cloakbrowser's `humanize: true` already patches page.click / page.mouse.move /
 * page.mouse.click / page.keyboard.type / page.hover / page.type with Bezier
 * paths, realistic typing, and CDP-trusted Shift handling. This engine just
 * routes tool calls to those patched methods — no duplicate timing code.
 */

import type { Page, Locator } from "playwright-core";
import { getPageForTarget } from "../browser/session.js";

interface Point { x: number; y: number }

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

// ── Mouse position tracking (for coord-based idle jitter) ────────────

interface MouseState { x: number; y: number }
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
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return page.getByRole(opts.role as any, opts.name ? { name: opts.name } : undefined);
  }
  if (opts.text) return page.getByText(opts.text);
  if (opts.label) return page.getByLabel(opts.label);
  return null;
}

function resolvedByLabel(opts: ClickTarget): string {
  if (opts.selector) return "selector";
  if (opts.role) return "role";
  if (opts.text) return "text";
  if (opts.label) return "label";
  return "coords";
}

// ── Engine ───────────────────────────────────────────────────────────

class HumanizerEngine {
  closeSession(targetId: string): void {
    clearMouseState(targetId);
  }

  async moveMouse(
    targetId: string,
    x: number,
    y: number,
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const page = getPageForTarget(targetId);
    const start = Date.now();
    await page.mouse.move(x, y);
    const state = getMouseState(targetId);
    state.x = x;
    state.y = y;
    return { totalMs: Date.now() - start, eventsDispatched: 1 };
  }

  async click(
    targetId: string,
    opts: ClickTarget & {
      button?: "left" | "right" | "middle";
      clickCount?: number;
      timeoutMs?: number;
    } = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; clickedAt: Point; resolvedBy: string }> {
    const page = getPageForTarget(targetId);
    const button = opts.button ?? "left";
    const clickCount = opts.clickCount ?? 1;
    const timeout = opts.timeoutMs ?? 15_000;
    const start = Date.now();
    const resolvedBy = resolvedByLabel(opts);

    const locator = resolveLocator(page, opts);
    if (locator) {
      await locator.click({ button, clickCount, timeout });
      const box = await locator.boundingBox({ timeout: 5_000 }).catch(() => null);
      const center: Point = box
        ? { x: box.x + box.width / 2, y: box.y + box.height / 2 }
        : { x: 0, y: 0 };
      const state = getMouseState(targetId);
      state.x = center.x;
      state.y = center.y;
      return { totalMs: Date.now() - start, eventsDispatched: 1, clickedAt: center, resolvedBy };
    }

    if (opts.x !== undefined && opts.y !== undefined) {
      await page.mouse.click(opts.x, opts.y, { button, clickCount });
      const state = getMouseState(targetId);
      state.x = opts.x;
      state.y = opts.y;
      return {
        totalMs: Date.now() - start,
        eventsDispatched: 1,
        clickedAt: { x: opts.x, y: opts.y },
        resolvedBy,
      };
    }

    throw new Error("Provide one of: selector, role (+ name), text, label, or x+y coordinates.");
  }

  async typeText(
    targetId: string,
    text: string,
    opts: { delayMs?: number } = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; charsTyped: number }> {
    const page = getPageForTarget(targetId);
    const start = Date.now();
    await page.keyboard.type(text, opts.delayMs !== undefined ? { delay: opts.delayMs } : undefined);
    return {
      totalMs: Date.now() - start,
      eventsDispatched: text.length,
      charsTyped: text.length,
    };
  }

  async scroll(
    targetId: string,
    deltaY: number,
    deltaX?: number,
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const page = getPageForTarget(targetId);
    const start = Date.now();
    await page.mouse.wheel(deltaX ?? 0, deltaY);
    return { totalMs: Date.now() - start, eventsDispatched: 1 };
  }

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

    while (Date.now() - start < durationMs) {
      const waitMs = Math.min(
        Math.round(rand(actionInterval * 0.7, actionInterval * 1.3)),
        durationMs - (Date.now() - start),
      );
      if (waitMs > 0) await sleep(waitMs);
      if (Date.now() - start >= durationMs) break;

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
