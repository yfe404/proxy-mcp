/**
 * CDP dispatch engine for human-like browser input.
 *
 * Singleton that manages persistent CdpSession per Chrome target, tracks
 * mouse position across calls, and dispatches Input.* events through CDP.
 */

import { CdpSession, getCdpTargets } from "../cdp-utils.js";
import { interceptorManager } from "../interceptors/manager.js";
import { generatePath, addRandomOffset, type Point } from "./path.js";
import { calculateKeyDelays, calculateScrollSteps, type TypingProfile, type ScrollOptions } from "./timing.js";

// ── Helpers ──────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rand(min: number, max: number): number {
  return min + Math.random() * (max - min);
}

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try { return JSON.stringify(e); } catch { return String(e); }
}

// ── CDP key code mapping ─────────────────────────────────────────────

interface KeyDef {
  key: string;
  code: string;
  keyCode: number;
  text?: string;
}

const SPECIAL_KEYS: Record<string, KeyDef> = {
  Backspace: { key: "Backspace", code: "Backspace", keyCode: 8 },
  Tab: { key: "Tab", code: "Tab", keyCode: 9, text: "\t" },
  Enter: { key: "Enter", code: "Enter", keyCode: 13, text: "\r" },
  Shift: { key: "Shift", code: "ShiftLeft", keyCode: 16 },
  Escape: { key: "Escape", code: "Escape", keyCode: 27 },
  " ": { key: " ", code: "Space", keyCode: 32, text: " " },
};

function charToKeyDef(ch: string): KeyDef {
  if (SPECIAL_KEYS[ch]) return SPECIAL_KEYS[ch];

  const lower = ch.toLowerCase();
  const isUpper = ch !== lower && ch === ch.toUpperCase();

  // Letters
  if (lower >= "a" && lower <= "z") {
    return {
      key: ch,
      code: `Key${lower.toUpperCase()}`,
      keyCode: lower.charCodeAt(0) - 32, // 'a' → 65
      text: ch,
    };
  }

  // Digits
  if (ch >= "0" && ch <= "9") {
    return {
      key: ch,
      code: `Digit${ch}`,
      keyCode: ch.charCodeAt(0),
      text: ch,
    };
  }

  // Punctuation / other — use generic mapping
  return {
    key: ch,
    code: "",
    keyCode: ch.charCodeAt(0),
    text: ch,
  };
}

// ── Target resolution ────────────────────────────────────────────────

async function getChromeTargetPort(targetId: string): Promise<number> {
  const chrome = interceptorManager.get("chrome");
  if (!chrome) throw new Error("Chrome interceptor not registered.");

  const meta = await chrome.getMetadata();
  const target = meta.activeTargets.find((t) => t.id === targetId);
  if (!target) throw new Error(`Chrome target '${targetId}' not found. Is it still running?`);

  const details = target.details as Record<string, unknown>;
  const port = details?.port;
  if (typeof port !== "number" || !Number.isFinite(port) || port <= 0) {
    throw new Error(`Chrome target '${targetId}' has no valid CDP port.`);
  }
  return port;
}

function targetUrlIsUserPage(url: unknown): boolean {
  if (typeof url !== "string") return false;
  const lower = url.toLowerCase();
  return lower.length > 0 && !lower.startsWith("devtools://") && !lower.startsWith("chrome://");
}

async function getPageWsUrl(port: number): Promise<string> {
  const targets = await getCdpTargets(port, { timeoutMs: 2000 });
  const pages = targets.filter((t) => t.type === "page");
  if (pages.length === 0) throw new Error("No page targets available.");

  const selected = pages.find((t) => targetUrlIsUserPage(t.url)) ?? pages[0];
  const wsUrl = selected.webSocketDebuggerUrl;
  if (typeof wsUrl !== "string" || !wsUrl) {
    throw new Error("Page target has no webSocketDebuggerUrl.");
  }
  return wsUrl;
}

// ── Bounding rect resolution ─────────────────────────────────────────

interface BoundingRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

async function resolveSelectorBounds(
  session: CdpSession,
  selector: string,
): Promise<BoundingRect> {
  const result = await session.send("Runtime.evaluate", {
    expression: `(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return { error: "Element not found: ${selector.replace(/"/g, '\\"')}" };
      const r = el.getBoundingClientRect();
      return { x: r.x, y: r.y, width: r.width, height: r.height };
    })()`,
    returnByValue: true,
    awaitPromise: false,
  });

  const remote = result.result as Record<string, unknown> | undefined;
  const value = remote?.value as Record<string, unknown> | undefined;
  if (!value || value.error) {
    throw new Error(typeof value?.error === "string" ? value.error : `Failed to resolve selector: ${selector}`);
  }

  return {
    x: Number(value.x),
    y: Number(value.y),
    width: Number(value.width),
    height: Number(value.height),
  };
}

// ── Engine ───────────────────────────────────────────────────────────

interface TargetState {
  session: CdpSession;
  mouseX: number;
  mouseY: number;
}

class HumanizerEngine {
  private _targets = new Map<string, TargetState>();

  /** Get or create a persistent CdpSession for a target. */
  async getSession(targetId: string): Promise<TargetState> {
    const existing = this._targets.get(targetId);
    if (existing && !existing.session.closed) return existing;

    // Clean up stale entry
    if (existing) this._targets.delete(targetId);

    const port = await getChromeTargetPort(targetId);
    const wsUrl = await getPageWsUrl(port);
    const session = await CdpSession.open(wsUrl);

    const state: TargetState = { session, mouseX: 0, mouseY: 0 };
    this._targets.set(targetId, state);
    return state;
  }

  /** Close the CdpSession for a target. */
  closeSession(targetId: string): void {
    const state = this._targets.get(targetId);
    if (state) {
      state.session.close();
      this._targets.delete(targetId);
    }
  }

  // ── Mouse movement ─────────────────────────────────────────────

  async moveMouse(
    targetId: string,
    x: number,
    y: number,
    durationMs?: number,
  ): Promise<{ totalMs: number; eventsDispatched: number }> {
    const state = await this.getSession(targetId);
    const from: Point = { x: state.mouseX, y: state.mouseY };
    const to: Point = { x, y };

    const path = generatePath(from, to, {
      baseDurationMs: durationMs ?? 600,
    });

    let eventsDispatched = 0;
    for (let i = 0; i < path.points.length; i++) {
      const pt = path.points[i];

      // Wait inter-point delay
      if (i > 0) {
        const delay = path.timestamps[i] - path.timestamps[i - 1];
        if (delay > 0) await sleep(delay);
      }

      await state.session.send("Input.dispatchMouseEvent", {
        type: "mouseMoved",
        x: pt.x,
        y: pt.y,
        button: "none",
        buttons: 0,
      });
      eventsDispatched++;
    }

    // Update tracked position
    const lastPt = path.points[path.points.length - 1];
    state.mouseX = lastPt.x;
    state.mouseY = lastPt.y;

    return { totalMs: path.totalMs, eventsDispatched };
  }

  // ── Click ──────────────────────────────────────────────────────

  async click(
    targetId: string,
    opts: {
      selector?: string;
      x?: number;
      y?: number;
      button?: "left" | "right" | "middle";
      clickCount?: number;
      moveDurationMs?: number;
    } = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; clickedAt: Point }> {
    const state = await this.getSession(targetId);
    const button = opts.button ?? "left";
    const clickCount = opts.clickCount ?? 1;

    let targetX: number;
    let targetY: number;

    if (opts.selector) {
      const bounds = await resolveSelectorBounds(state.session, opts.selector);
      const center: Point = {
        x: bounds.x + bounds.width / 2,
        y: bounds.y + bounds.height / 2,
      };
      const offset = addRandomOffset(center, bounds);
      targetX = offset.x;
      targetY = offset.y;
    } else if (opts.x !== undefined && opts.y !== undefined) {
      targetX = opts.x;
      targetY = opts.y;
    } else {
      throw new Error("Either selector or x+y coordinates are required.");
    }

    // Move to target
    const moveResult = await this.moveMouse(targetId, targetX, targetY, opts.moveDurationMs);
    let eventsDispatched = moveResult.eventsDispatched;
    let totalMs = moveResult.totalMs;

    const cdpButton = button === "right" ? "right" : button === "middle" ? "middle" : "left";
    const buttons = button === "right" ? 2 : button === "middle" ? 4 : 1;

    // Small pause before clicking (human hesitation)
    const preClickDelay = Math.round(rand(30, 80));
    await sleep(preClickDelay);
    totalMs += preClickDelay;

    for (let c = 0; c < clickCount; c++) {
      // mousePressed
      await state.session.send("Input.dispatchMouseEvent", {
        type: "mousePressed",
        x: targetX,
        y: targetY,
        button: cdpButton,
        buttons,
        clickCount: c + 1,
      });
      eventsDispatched++;

      // Brief hold
      const holdMs = Math.round(rand(40, 100));
      await sleep(holdMs);
      totalMs += holdMs;

      // mouseReleased
      await state.session.send("Input.dispatchMouseEvent", {
        type: "mouseReleased",
        x: targetX,
        y: targetY,
        button: cdpButton,
        buttons: 0,
        clickCount: c + 1,
      });
      eventsDispatched++;

      // Inter-click pause for multi-click
      if (c < clickCount - 1) {
        const interClickMs = Math.round(rand(50, 120));
        await sleep(interClickMs);
        totalMs += interClickMs;
      }
    }

    return { totalMs, eventsDispatched, clickedAt: { x: targetX, y: targetY } };
  }

  // ── Typing ─────────────────────────────────────────────────────

  async typeText(
    targetId: string,
    text: string,
    profile: TypingProfile = {},
  ): Promise<{ totalMs: number; eventsDispatched: number; charsTyped: number }> {
    const state = await this.getSession(targetId);
    const keyDelays = calculateKeyDelays(text, profile);

    let totalMs = 0;
    let eventsDispatched = 0;

    for (const { key, delayMs } of keyDelays) {
      // Wait before keystroke
      await sleep(delayMs);
      totalMs += delayMs;

      const keyDef = charToKeyDef(key);
      const needsShift = key !== key.toLowerCase() && key === key.toUpperCase() && key.length === 1;

      // Shift down if needed
      if (needsShift) {
        await state.session.send("Input.dispatchKeyEvent", {
          type: "keyDown",
          key: "Shift",
          code: "ShiftLeft",
          windowsVirtualKeyCode: 16,
          nativeVirtualKeyCode: 16,
          modifiers: 8, // shift modifier
        });
        eventsDispatched++;
      }

      // keyDown (no text — character insertion happens via the char event)
      await state.session.send("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: keyDef.key,
        code: keyDef.code,
        windowsVirtualKeyCode: keyDef.keyCode,
        nativeVirtualKeyCode: keyDef.keyCode,
        ...(needsShift ? { modifiers: 8 } : {}),
      });
      eventsDispatched++;

      // char event for text-producing keys
      if (keyDef.text) {
        await state.session.send("Input.dispatchKeyEvent", {
          type: "char",
          key: keyDef.key,
          code: keyDef.code,
          text: keyDef.text,
          unmodifiedText: keyDef.text,
          ...(needsShift ? { modifiers: 8 } : {}),
        });
        eventsDispatched++;
      }

      // Brief key hold
      const holdMs = Math.round(rand(20, 60));
      await sleep(holdMs);
      totalMs += holdMs;

      // keyUp
      await state.session.send("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: keyDef.key,
        code: keyDef.code,
        windowsVirtualKeyCode: keyDef.keyCode,
        nativeVirtualKeyCode: keyDef.keyCode,
        ...(needsShift ? { modifiers: 8 } : {}),
      });
      eventsDispatched++;

      // Shift up if needed
      if (needsShift) {
        await state.session.send("Input.dispatchKeyEvent", {
          type: "keyUp",
          key: "Shift",
          code: "ShiftLeft",
          windowsVirtualKeyCode: 16,
          nativeVirtualKeyCode: 16,
        });
        eventsDispatched++;
      }
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
    const state = await this.getSession(targetId);
    const scrollSteps = calculateScrollSteps({
      deltaY,
      deltaX,
      durationMs: durationMs ?? 400,
    });

    let totalMs = 0;
    let eventsDispatched = 0;

    for (const step of scrollSteps) {
      await sleep(step.delayMs);
      totalMs += step.delayMs;

      await state.session.send("Input.dispatchMouseEvent", {
        type: "mouseWheel",
        x: state.mouseX,
        y: state.mouseY,
        deltaX: step.deltaX,
        deltaY: step.deltaY,
        button: "none",
        buttons: 0,
      });
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
    const state = await this.getSession(targetId);
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

      // Random action: micro mouse jitter or micro scroll
      if (Math.random() < scrollChance) {
        // Micro scroll
        const microDelta = Math.round(rand(-20, 20));
        if (microDelta !== 0) {
          await state.session.send("Input.dispatchMouseEvent", {
            type: "mouseWheel",
            x: state.mouseX,
            y: state.mouseY,
            deltaX: 0,
            deltaY: microDelta,
            button: "none",
            buttons: 0,
          });
          eventsDispatched++;
        }
      } else {
        // Mouse jitter
        const jx = Math.round(state.mouseX + rand(-jitterRadius, jitterRadius));
        const jy = Math.round(state.mouseY + rand(-jitterRadius, jitterRadius));

        await state.session.send("Input.dispatchMouseEvent", {
          type: "mouseMoved",
          x: jx,
          y: jy,
          button: "none",
          buttons: 0,
        });
        eventsDispatched++;

        state.mouseX = jx;
        state.mouseY = jy;
      }
    }

    return { totalMs: Date.now() - start, eventsDispatched };
  }
}

/** Singleton humanizer engine instance. */
export const humanizerEngine = new HumanizerEngine();
