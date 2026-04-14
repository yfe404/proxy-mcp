/**
 * Humanizer MCP tools — thin wrappers over cloakbrowser-patched Playwright.
 *
 * cloakbrowser's `humanize: true` (on by default) already provides Bezier
 * mouse paths, realistic typing with CDP-trusted Shift handling, and smooth
 * scrolling. These tools just expose the patched methods to MCP callers.
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
    "Move mouse to target coordinates. cloakbrowser's humanize patches " +
    "page.mouse.move with a Bezier-curved path.",
    {
      target_id: z.string().describe("Browser target ID from interceptor_browser_launch"),
      x: z.number().describe("Destination X coordinate"),
      y: z.number().describe("Destination Y coordinate"),
    },
    async ({ target_id, x, y }) => {
      try {
        const result = await humanizerEngine.moveMouse(target_id, x, y);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "move",
              destination: { x, y },
              stats: { total_ms: result.totalMs, events_dispatched: result.eventsDispatched },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", target_id, action: "move", error: errorToString(e) }) }] };
      }
    },
  );

  // ── humanizer_click ────────────────────────────────────────────

  server.tool(
    "humanizer_click",
    "Click an element. Pass one of: selector (CSS/XPath), role + optional name, " +
    "text, label, or raw x+y coords as fallback. cloakbrowser's humanize handles " +
    "the Bezier path and click timing; locator-based calls auto-wait for visible.",
    {
      target_id: z.string().describe("Browser target ID from interceptor_browser_launch"),
      selector: z.string().optional().describe("CSS or XPath selector (e.g. 'button.submit', '//button[@id=\"go\"]')"),
      role: z.string().optional().describe("ARIA role (e.g. 'button', 'link', 'textbox')"),
      name: z.string().optional().describe("Accessible name; used with role (e.g. 'Sign in')"),
      text: z.string().optional().describe("Visible text to match (e.g. 'Accept cookies')"),
      label: z.string().optional().describe("Form-field label text (e.g. 'Email address')"),
      x: z.number().optional().describe("X coordinate fallback when no locator is given"),
      y: z.number().optional().describe("Y coordinate fallback when no locator is given"),
      button: z.enum(["left", "right", "middle"]).optional().default("left")
        .describe("Mouse button (default: left)"),
      click_count: z.number().optional().default(1)
        .describe("Number of clicks (default: 1, use 2 for double-click)"),
      timeout_ms: z.number().optional().default(15000)
        .describe("Max ms to wait for locator to be visible + actionable (default: 15000)"),
    },
    async ({ target_id, selector, role, name, text, label, x, y, button, click_count, timeout_ms }) => {
      try {
        const result = await humanizerEngine.click(target_id, {
          selector,
          role,
          name,
          text,
          label,
          x,
          y,
          button,
          clickCount: click_count,
          timeoutMs: timeout_ms,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "click",
              resolved_by: result.resolvedBy,
              clicked_at: result.clickedAt,
              button,
              click_count,
              stats: { total_ms: result.totalMs, events_dispatched: result.eventsDispatched },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", target_id, action: "click", error: errorToString(e) }) }] };
      }
    },
  );

  // ── humanizer_type ─────────────────────────────────────────────

  server.tool(
    "humanizer_type",
    "Type text into the focused element. cloakbrowser's humanize patches " +
    "page.keyboard.type with realistic per-char timing and CDP-trusted Shift " +
    "handling (uppercase + symbols preserved).",
    {
      target_id: z.string().describe("Browser target ID from interceptor_browser_launch"),
      text: z.string().describe("Text to type"),
      delay_ms: z.number().optional()
        .describe("Extra delay per character in ms. Omit to let cloakbrowser pick its own humanized cadence."),
    },
    async ({ target_id, text, delay_ms }) => {
      try {
        const result = await humanizerEngine.typeText(target_id, text, { delayMs: delay_ms });
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
              },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", target_id, action: "type", error: errorToString(e) }) }] };
      }
    },
  );

  // ── humanizer_scroll ───────────────────────────────────────────

  server.tool(
    "humanizer_scroll",
    "Dispatch a wheel event. Raw page.mouse.wheel — single event, not multi-step.",
    {
      target_id: z.string().describe("Browser target ID from interceptor_browser_launch"),
      delta_y: z.number().describe("Vertical scroll delta in pixels (positive = scroll down)"),
      delta_x: z.number().optional().default(0)
        .describe("Horizontal scroll delta in pixels (default: 0)"),
    },
    async ({ target_id, delta_y, delta_x }) => {
      try {
        const result = await humanizerEngine.scroll(target_id, delta_y, delta_x);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              target_id,
              action: "scroll",
              delta: { x: delta_x, y: delta_y },
              stats: { total_ms: result.totalMs, events_dispatched: result.eventsDispatched },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", target_id, action: "scroll", error: errorToString(e) }) }] };
      }
    },
  );

  // ── humanizer_idle ─────────────────────────────────────────────

  server.tool(
    "humanizer_idle",
    "Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls. " +
    "Keeps the page 'alive' to avoid idle detection by bot-detection scripts.",
    {
      target_id: z.string().describe("Browser target ID from interceptor_browser_launch"),
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
              stats: { total_ms: result.totalMs, events_dispatched: result.eventsDispatched },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", target_id, action: "idle", error: errorToString(e) }) }] };
      }
    },
  );
}
