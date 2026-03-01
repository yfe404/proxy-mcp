/**
 * Humanizer MCP tools — human-like browser input via CDP.
 *
 * Dispatches realistic mouse, keyboard, and scroll events through the
 * Chrome DevTools Protocol. Binds to target_id (Chrome interceptor target),
 * not devtools_session_id — the humanizer manages its own CdpSession.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { humanizerEngine } from "../humanizer/engine.js";

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try { return JSON.stringify(e); } catch { return String(e); }
}

export function registerHumanizerTools(server: McpServer): void {
  // ── humanizer_move ─────────────────────────────────────────────

  server.tool(
    "humanizer_move",
    "Move mouse along a human-like Bezier curve to target coordinates. " +
    "Uses Fitts's law velocity scaling and eased timing profile.",
    {
      target_id: z.string().describe("Chrome target ID from interceptor_chrome_launch"),
      x: z.number().describe("Destination X coordinate"),
      y: z.number().describe("Destination Y coordinate"),
      duration_ms: z.number().optional().default(600)
        .describe("Base duration in ms before Fitts scaling (default: 600)"),
    },
    async ({ target_id, x, y, duration_ms }) => {
      try {
        const result = await humanizerEngine.moveMouse(target_id, x, y, duration_ms);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "move",
              destination: { x, y },
              stats: {
                total_ms: result.totalMs,
                events_dispatched: result.eventsDispatched,
              },
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", target_id, action: "move", error: errorToString(e) }),
          }],
        };
      }
    },
  );

  // ── humanizer_click ────────────────────────────────────────────

  server.tool(
    "humanizer_click",
    "Move to an element (by CSS selector) or coordinates, then click with human-like timing. " +
    "Supports left/right/middle button and multi-click (double-click, etc.).",
    {
      target_id: z.string().describe("Chrome target ID from interceptor_chrome_launch"),
      selector: z.string().optional().describe("CSS selector to click (resolved via getBoundingClientRect)"),
      x: z.number().optional().describe("X coordinate (used if selector is not provided)"),
      y: z.number().optional().describe("Y coordinate (used if selector is not provided)"),
      button: z.enum(["left", "right", "middle"]).optional().default("left")
        .describe("Mouse button (default: left)"),
      click_count: z.number().optional().default(1)
        .describe("Number of clicks (default: 1, use 2 for double-click)"),
      move_duration_ms: z.number().optional().default(600)
        .describe("Base duration for mouse movement (default: 600)"),
    },
    async ({ target_id, selector, x, y, button, click_count, move_duration_ms }) => {
      try {
        const result = await humanizerEngine.click(target_id, {
          selector,
          x,
          y,
          button,
          clickCount: click_count,
          moveDurationMs: move_duration_ms,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "click",
              clicked_at: result.clickedAt,
              button,
              click_count,
              stats: {
                total_ms: result.totalMs,
                events_dispatched: result.eventsDispatched,
              },
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", target_id, action: "click", error: errorToString(e) }),
          }],
        };
      }
    },
  );

  // ── humanizer_type ─────────────────────────────────────────────

  server.tool(
    "humanizer_type",
    "Type text with human-like keystroke timing. " +
    "Models per-character delays based on WPM, bigram frequency, shift penalty, " +
    "word boundary pauses, and optional typo injection with backspace correction.",
    {
      target_id: z.string().describe("Chrome target ID from interceptor_chrome_launch"),
      text: z.string().describe("Text to type"),
      wpm: z.number().optional().default(40)
        .describe("Typing speed in words per minute (default: 40)"),
      error_rate: z.number().optional().default(0)
        .describe("Typo probability per character, 0-1 (default: 0)"),
    },
    async ({ target_id, text, wpm, error_rate }) => {
      try {
        const result = await humanizerEngine.typeText(target_id, text, {
          wpm,
          errorRate: error_rate,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "type",
              text_length: text.length,
              stats: {
                total_ms: result.totalMs,
                events_dispatched: result.eventsDispatched,
                chars_typed: result.charsTyped,
                effective_wpm: text.length > 0
                  ? Math.round((text.length / 5) / (result.totalMs / 60_000))
                  : 0,
              },
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", target_id, action: "type", error: errorToString(e) }),
          }],
        };
      }
    },
  );

  // ── humanizer_scroll ───────────────────────────────────────────

  server.tool(
    "humanizer_scroll",
    "Scroll with natural acceleration/deceleration using easeInOutQuad velocity distribution. " +
    "Dispatches multiple wheel events to simulate human scroll behavior.",
    {
      target_id: z.string().describe("Chrome target ID from interceptor_chrome_launch"),
      delta_y: z.number().describe("Vertical scroll delta in pixels (positive = scroll down)"),
      delta_x: z.number().optional().default(0)
        .describe("Horizontal scroll delta in pixels (default: 0)"),
      duration_ms: z.number().optional().default(400)
        .describe("Total scroll duration in ms (default: 400)"),
    },
    async ({ target_id, delta_y, delta_x, duration_ms }) => {
      try {
        const result = await humanizerEngine.scroll(target_id, delta_y, delta_x, duration_ms);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "scroll",
              delta: { x: delta_x, y: delta_y },
              stats: {
                total_ms: result.totalMs,
                events_dispatched: result.eventsDispatched,
              },
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", target_id, action: "scroll", error: errorToString(e) }),
          }],
        };
      }
    },
  );

  // ── humanizer_idle ─────────────────────────────────────────────

  server.tool(
    "humanizer_idle",
    "Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls. " +
    "Keeps the page 'alive' to avoid idle detection by bot-detection scripts.",
    {
      target_id: z.string().describe("Chrome target ID from interceptor_chrome_launch"),
      duration_ms: z.number().describe("How long to simulate idle behavior in ms"),
      intensity: z.enum(["subtle", "normal"]).optional().default("subtle")
        .describe("Idle intensity: 'subtle' (±3px jitter) or 'normal' (±8px jitter, more scrolls)"),
    },
    async ({ target_id, duration_ms, intensity }) => {
      try {
        const result = await humanizerEngine.idle(target_id, duration_ms, intensity);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "idle",
              requested_ms: duration_ms,
              intensity,
              stats: {
                total_ms: result.totalMs,
                events_dispatched: result.eventsDispatched,
              },
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", target_id, action: "idle", error: errorToString(e) }),
          }],
        };
      }
    },
  );
}
