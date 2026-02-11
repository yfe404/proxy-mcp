/**
 * Persistent session tools — manage on-disk traffic recordings and HAR exports.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { truncateResult } from "../utils.js";

function toError(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

export function registerSessionTools(server: McpServer): void {
  server.tool(
    "proxy_session_start",
    "Start persistent on-disk capture for the current proxy run.",
    {
      session_name: z.string().optional().describe("Optional session name"),
      capture_profile: z.enum(["preview", "full"]).optional().default("preview")
        .describe("preview=body previews only, full=full request/response bodies"),
      storage_dir: z.string().optional().describe("Custom storage directory"),
      max_disk_mb: z.number().optional().default(1024).describe("Session disk cap in MB"),
    },
    async ({ session_name, capture_profile, storage_dir, max_disk_mb }) => {
      try {
        if (!proxyManager.isRunning()) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "Proxy is not running. Start it first with proxy_start." }) }] };
        }
        const session = await proxyManager.startSession({
          sessionName: session_name,
          captureProfile: capture_profile,
          storageDir: storage_dir,
          maxDiskMb: max_disk_mb,
        });
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", session }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_session_stop",
    "Stop persistent on-disk capture and finalize the active session.",
    {},
    async () => {
      try {
        const session = await proxyManager.stopSession();
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", session }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_session_status",
    "Get current persistent capture runtime status.",
    {},
    async () => ({
      content: [{ type: "text", text: JSON.stringify({ status: "success", ...proxyManager.getSessionStatus() }) }],
    }),
  );

  server.tool(
    "proxy_list_sessions",
    "List recorded sessions in storage.",
    {},
    async () => {
      try {
        const sessions = await proxyManager.listSessions();
        return {
          content: [{ type: "text", text: truncateResult({ status: "success", count: sessions.length, sessions }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_get_session",
    "Get manifest/details for a specific recorded session.",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      try {
        const session = await proxyManager.getSession(session_id);
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", session }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_query_session",
    "Query indexed session exchanges with filters and pagination.",
    {
      session_id: z.string().describe("Session ID"),
      limit: z.number().optional().default(50),
      offset: z.number().optional().default(0),
      sort: z.enum(["asc", "desc"]).optional().default("desc"),
      method: z.string().optional().describe("HTTP method filter"),
      hostname_contains: z.string().optional().describe("Filter by hostname substring"),
      url_contains: z.string().optional().describe("Filter by URL substring"),
      status_code: z.number().optional().describe("HTTP response status code filter"),
      from_ts: z.number().optional().describe("Unix ms lower-bound timestamp"),
      to_ts: z.number().optional().describe("Unix ms upper-bound timestamp"),
      text: z.string().optional().describe("Generic text filter"),
    },
    async ({ session_id, limit, offset, sort, method, hostname_contains, url_contains, status_code, from_ts, to_ts, text }) => {
      try {
        const result = await proxyManager.querySession(session_id, {
          limit,
          offset,
          sort,
          method,
          hostnameContains: hostname_contains,
          urlContains: url_contains,
          statusCode: status_code,
          fromTs: from_ts,
          toTs: to_ts,
          text,
        });
        return {
          content: [{ type: "text", text: truncateResult({ status: "success", ...result }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_get_session_exchange",
    "Get one exchange from a recorded session by seq or exchange ID.",
    {
      session_id: z.string().describe("Session ID"),
      seq: z.number().optional().describe("Sequence number in session"),
      exchange_id: z.string().optional().describe("Original exchange ID"),
      include_body: z.boolean().optional().default(true).describe("Include persisted full body data when available"),
    },
    async ({ session_id, seq, exchange_id, include_body }) => {
      try {
        if (seq === undefined && !exchange_id) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "Provide seq or exchange_id." }) }] };
        }
        const result = await proxyManager.getSessionExchange(session_id, {
          seq,
          exchangeId: exchange_id,
          includeBody: include_body,
        });
        return {
          content: [{ type: "text", text: truncateResult({ status: "success", ...result }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_export_har",
    "Export a recorded session (or filtered subset) to HAR format.",
    {
      session_id: z.string().describe("Session ID"),
      output_file: z.string().optional().describe("Output HAR file path"),
      include_bodies: z.boolean().optional().default(true).describe("Include body text when available"),
      method: z.string().optional(),
      hostname_contains: z.string().optional(),
      url_contains: z.string().optional(),
      status_code: z.number().optional(),
      from_ts: z.number().optional(),
      to_ts: z.number().optional(),
      text: z.string().optional(),
      sort: z.enum(["asc", "desc"]).optional().default("asc"),
    },
    async ({ session_id, output_file, include_bodies, method, hostname_contains, url_contains, status_code, from_ts, to_ts, text, sort }) => {
      try {
        const exported = await proxyManager.exportSessionHar(session_id, {
          outputFile: output_file,
          includeBodies: include_bodies,
          query: {
            method,
            hostnameContains: hostname_contains,
            urlContains: url_contains,
            statusCode: status_code,
            fromTs: from_ts,
            toTs: to_ts,
            text,
            sort,
          },
        });
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", ...exported }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_delete_session",
    "Delete a recorded session from disk.",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      try {
        await proxyManager.deleteSession(session_id);
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", deleted: session_id }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_session_recover",
    "Rebuild session indexes from records after crash/corruption.",
    {
      session_id: z.string().optional().describe("Recover only this session (default: recover all sessions)"),
    },
    async ({ session_id }) => {
      try {
        const result = await proxyManager.recoverSession(session_id);
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", ...result }) }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: toError(e) }) }] };
      }
    },
  );
}
