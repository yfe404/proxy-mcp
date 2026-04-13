/**
 * Browser DevTools-equivalent MCP tools — Playwright-driven.
 *
 * Replaces the former chrome-devtools-mcp sidecar + CDP bridge. Each tool
 * takes a browser target_id (from interceptor_browser_launch) and drives
 * the bound Playwright Page directly.
 *
 * Tools exposed:
 *   interceptor_browser_snapshot          — a11y tree
 *   interceptor_browser_screenshot        — screenshot, optional save
 *   interceptor_browser_list_console      — buffered console messages
 *   interceptor_browser_list_cookies      — paginated cookie list
 *   interceptor_browser_get_cookie        — full cookie by cookie_id
 *   interceptor_browser_list_storage_keys — local/session storage keys
 *   interceptor_browser_get_storage_value — full storage value by item_id
 *   interceptor_browser_list_network_fields — header fields from proxy traffic
 *   interceptor_browser_get_network_field   — full header value by field_id
 *
 * Network listing intentionally sources from proxyManager — the MITM is
 * the single source of truth for captured HTTP, and it works independently
 * of whether the browser emitted a CDP event.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import { proxyManager } from "../state.js";
import { truncateResult } from "../utils.js";
import { getEntry, getPageForTarget } from "../browser/session.js";

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  try { return JSON.stringify(e); } catch { return String(e); }
}

const DEFAULT_VALUE_MAX_CHARS = 256;
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const HARD_VALUE_CAP_CHARS = 20000;

function normalizeLimit(limit: number | undefined): number {
  const n = limit ?? DEFAULT_LIST_LIMIT;
  if (!Number.isFinite(n)) return DEFAULT_LIST_LIMIT;
  return Math.max(1, Math.min(MAX_LIST_LIMIT, Math.trunc(n)));
}

function normalizeOffset(offset: number | undefined): number {
  const n = offset ?? 0;
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.trunc(n));
}

function toBase64UrlUtf8(s: string): string {
  return Buffer.from(s, "utf8")
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

function fromBase64UrlUtf8(s: string): string {
  let b64 = s.replaceAll("-", "+").replaceAll("_", "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return Buffer.from(b64, "base64").toString("utf8");
}

function capValue(value: string, maxChars: number): { value: string; valueLength: number; truncated: boolean; maxChars: number } {
  const valueLength = value.length;
  const effectiveMax = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(maxChars)));
  if (effectiveMax === 0) {
    return { value, valueLength, truncated: false, maxChars: 0 };
  }
  if (valueLength <= effectiveMax) {
    return { value, valueLength, truncated: false, maxChars: effectiveMax };
  }
  return { value: value.slice(0, effectiveMax) + "...", valueLength, truncated: true, maxChars: effectiveMax };
}

function cookieStableId(cookie: { name?: string; domain?: string; path?: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; partitionKey?: string }): string {
  const parts = [
    cookie.name ?? "",
    cookie.domain ?? "",
    cookie.path ?? "",
    String(!!cookie.secure),
    String(!!cookie.httpOnly),
    cookie.sameSite ?? "",
    cookie.partitionKey ?? "",
  ];
  return `ck_${createHash("sha1").update(parts.join("|"), "utf8").digest("hex")}`;
}

function getOriginFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

export function registerDevToolsTools(server: McpServer): void {
  // ── snapshot ──────────────────────────────────────────────────

  server.tool(
    "interceptor_browser_snapshot",
    "Take an ARIA accessibility snapshot of the bound page (YAML-formatted role tree). " +
    "Great for LLM-driven page understanding without parsing HTML.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      selector: z.string().optional().default("body").describe("Root selector to snapshot (default: 'body')"),
      mode: z.enum(["default", "ai"]).optional().default("default").describe("Snapshot mode — 'ai' adds ref attributes for locator reuse"),
    },
    async ({ target_id, selector, mode }) => {
      try {
        const page = getPageForTarget(target_id);
        const snapshot = await page.locator(selector).ariaSnapshot({ mode });
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              url: page.url(),
              title: await page.title().catch(() => ""),
              root: selector,
              snapshot,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ── screenshot ────────────────────────────────────────────────

  server.tool(
    "interceptor_browser_screenshot",
    "Take a screenshot of the bound page. Saves to file_path if provided; otherwise reports byte count without embedding the image.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      file_path: z.string().optional().describe("Optional path to save screenshot"),
      format: z.enum(["png", "jpeg"]).optional().default("png").describe("Image format (default: png)"),
      full_page: z.boolean().optional().default(false).describe("Capture the full scrollable page"),
      quality: z.number().optional().describe("JPEG quality 0-100 (ignored for png)"),
    },
    async ({ target_id, file_path, format, full_page, quality }) => {
      try {
        const page = getPageForTarget(target_id);
        const buffer = await page.screenshot({
          type: format,
          fullPage: full_page,
          ...(format === "jpeg" && quality !== undefined ? { quality } : {}),
        });

        let saved = false;
        if (file_path) {
          await mkdir(dirname(file_path), { recursive: true });
          await writeFile(file_path, buffer);
          saved = true;
        }

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              format,
              full_page,
              bytes: buffer.length,
              ...(file_path ? { file_path, saved } : {}),
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ── console ───────────────────────────────────────────────────

  server.tool(
    "interceptor_browser_list_console",
    "List console messages buffered since the browser was launched. Types: log, info, warning, error, debug, etc.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      types: z.array(z.string()).optional().describe("Filter by console message types"),
      text_filter: z.string().optional().describe("Filter by text substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max messages to return (default: 50, max: 500)"),
    },
    async ({ target_id, types, text_filter, offset, limit }) => {
      try {
        const entry = getEntry(target_id);
        let msgs = entry.consoleBuffer;
        if (types && types.length > 0) {
          const set = new Set(types.map((t) => t.toLowerCase()));
          msgs = msgs.filter((m) => set.has(m.type.toLowerCase()));
        }
        if (text_filter) {
          const needle = text_filter.toLowerCase();
          msgs = msgs.filter((m) => m.text.toLowerCase().includes(needle));
        }
        const total = msgs.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const page = msgs.slice(o, o + l);

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              total,
              offset: o,
              limit: l,
              showing: page.length,
              messages: page,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ── cookies ───────────────────────────────────────────────────

  server.tool(
    "interceptor_browser_list_cookies",
    "List cookies from the browser context with pagination and truncated value previews.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      url_filter: z.string().optional().describe("Filter cookies by domain/path substring"),
      domain_filter: z.string().optional().describe("Filter cookies by domain substring"),
      name_filter: z.string().optional().describe("Filter cookies by name substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max cookies to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for cookie value previews (default: 256)"),
      sort: z.enum(["name", "domain", "expires"]).optional().default("name").describe("Sort order (default: name)"),
    },
    async ({ target_id, url_filter, domain_filter, name_filter, offset, limit, value_max_chars, sort }) => {
      try {
        const entry = getEntry(target_id);
        const cookies = await entry.context.cookies();

        const urlNeedle = url_filter?.toLowerCase();
        const domainNeedle = domain_filter?.toLowerCase();
        const nameNeedle = name_filter?.toLowerCase();

        const filtered = cookies.filter((c) => {
          if (urlNeedle && !`${c.domain}${c.path}`.toLowerCase().includes(urlNeedle)) return false;
          if (domainNeedle && !c.domain.toLowerCase().includes(domainNeedle)) return false;
          if (nameNeedle && !c.name.toLowerCase().includes(nameNeedle)) return false;
          return true;
        });

        const sorted = filtered.sort((a, b) => {
          switch (sort) {
            case "domain": return a.domain.localeCompare(b.domain) || a.name.localeCompare(b.name);
            case "expires": return (a.expires ?? 0) - (b.expires ?? 0) || a.domain.localeCompare(b.domain) || a.name.localeCompare(b.name);
            case "name":
            default: return a.name.localeCompare(b.name) || a.domain.localeCompare(b.domain);
          }
        });

        const total = sorted.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const page = sorted.slice(o, o + l);

        const valueCap = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));

        const summaries = page.map((c) => {
          const capped = capValue(c.value, valueCap);
          return {
            cookie_id: cookieStableId(c),
            name: c.name,
            domain: c.domain,
            path: c.path,
            expires: c.expires ?? null,
            httpOnly: c.httpOnly,
            secure: c.secure,
            sameSite: c.sameSite ?? null,
            value_preview: capped.value,
            value_length: capped.valueLength,
            value_truncated: capped.truncated,
          };
        });

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              total,
              offset: o,
              limit: l,
              showing: summaries.length,
              cookies: summaries,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_browser_get_cookie",
    "Get one cookie by cookie_id with full value (subject to a hard cap to keep output bounded).",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      cookie_id: z.string().describe("cookie_id from interceptor_browser_list_cookies"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for cookie value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ target_id, cookie_id, value_max_chars }) => {
      try {
        const entry = getEntry(target_id);
        const cookies = await entry.context.cookies();
        const found = cookies.find((c) => cookieStableId(c) === cookie_id) ?? null;
        if (!found) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Cookie '${cookie_id}' not found. Re-run list tool.` }) }] };
        }
        const capped = capValue(found.value, Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS))));
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              cookie_id,
              cookie: { ...found, value: capped.value },
              value_length: capped.valueLength,
              value_truncated: capped.truncated,
              value_max_chars: capped.maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ── storage ───────────────────────────────────────────────────

  server.tool(
    "interceptor_browser_list_storage_keys",
    "List localStorage/sessionStorage keys for the current origin with pagination and truncated value previews.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      storage_type: z.enum(["local", "session"]).describe("Storage type"),
      origin: z.string().optional().describe("Optional origin override (must match current page origin)"),
      key_filter: z.string().optional().describe("Filter by key substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max items to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for storage value previews (default: 256)"),
    },
    async ({ target_id, storage_type, origin, key_filter, offset, limit, value_max_chars }) => {
      try {
        const page = getPageForTarget(target_id);
        const pageUrl = page.url();
        const currentOrigin = getOriginFromUrl(pageUrl);
        if (!currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `No http(s) origin available for current page URL: '${pageUrl}'` }) }] };
        }
        if (origin && origin !== currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `origin '${origin}' does not match current origin '${currentOrigin}'. Navigate first.` }) }] };
        }

        const previewLen = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));
        const keyNeedle = (key_filter ?? "").toLowerCase();

        const items = await page.evaluate(
          ({ stType, keyFilter, maxChars }) => {
            const storage = stType === "local" ? localStorage : sessionStorage;
            const out: { key: string; valuePreview: string; valueLength: number }[] = [];
            for (let i = 0; i < storage.length; i++) {
              const k = storage.key(i);
              if (typeof k !== "string") continue;
              if (keyFilter && !k.toLowerCase().includes(keyFilter)) continue;
              const raw = storage.getItem(k);
              const v = typeof raw === "string" ? raw : "";
              out.push({ key: k, valuePreview: maxChars > 0 ? v.slice(0, maxChars) : "", valueLength: v.length });
            }
            out.sort((a, b) => a.key.localeCompare(b.key));
            return out;
          },
          { stType: storage_type, keyFilter: keyNeedle, maxChars: previewLen },
        );

        const total = items.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const pageItems = items.slice(o, o + l);

        const summaries = pageItems.map((x) => ({
          item_id: `st.${storage_type}.${toBase64UrlUtf8(currentOrigin)}.${toBase64UrlUtf8(x.key)}`,
          key: x.key,
          value_preview: x.valuePreview,
          value_length: x.valueLength,
          value_truncated: previewLen > 0 ? x.valueLength > previewLen : (x.valueLength > 0),
        }));

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              origin: currentOrigin,
              storage_type,
              total,
              offset: o,
              limit: l,
              showing: summaries.length,
              items: summaries,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_browser_get_storage_value",
    "Get one localStorage/sessionStorage value by item_id.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      storage_type: z.enum(["local", "session"]).describe("Storage type"),
      item_id: z.string().describe("item_id from interceptor_browser_list_storage_keys"),
      origin: z.string().optional().describe("Optional origin override (must match current page origin)"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for returned value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ target_id, storage_type, item_id, origin, value_max_chars }) => {
      try {
        const parts = item_id.split(".");
        if (parts.length !== 4 || parts[0] !== "st") {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid item_id '${item_id}'` }) }] };
        }
        const itemType = parts[1];
        const itemOrigin = fromBase64UrlUtf8(parts[2]);
        const itemKey = fromBase64UrlUtf8(parts[3]);
        if (itemType !== storage_type) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `item_id storage_type '${itemType}' does not match requested '${storage_type}'` }) }] };
        }

        const page = getPageForTarget(target_id);
        const pageUrl = page.url();
        const currentOrigin = getOriginFromUrl(pageUrl);
        if (!currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `No http(s) origin available for current page URL: '${pageUrl}'` }) }] };
        }
        if (origin && origin !== currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `origin '${origin}' does not match current origin '${currentOrigin}'. Navigate first.` }) }] };
        }
        if (itemOrigin !== currentOrigin) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `item_id origin '${itemOrigin}' does not match current origin '${currentOrigin}'. Navigate first.` }) }] };
        }

        const maxChars = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS)));
        const result = await page.evaluate(
          ({ stType, key, maxChars: mc }) => {
            const storage = stType === "local" ? localStorage : sessionStorage;
            const raw = storage.getItem(key);
            const v = typeof raw === "string" ? raw : "";
            const valueLength = v.length;
            const truncated = mc > 0 && valueLength > mc;
            const value = mc > 0 ? (truncated ? v.slice(0, mc) : v) : v;
            return { key, value, valueLength, truncated };
          },
          { stType: storage_type, key: itemKey, maxChars },
        );

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              origin: currentOrigin,
              storage_type,
              item_id,
              key: result.key,
              value: result.value,
              value_length: result.valueLength,
              value_truncated: result.truncated,
              value_max_chars: maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  // ── network fields (from MITM proxy capture) ───────────────────

  server.tool(
    "interceptor_browser_list_network_fields",
    "List request/response header fields from proxy-captured traffic since the browser was launched, with pagination and truncation.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      direction: z.enum(["request", "response", "both"]).optional().default("both").describe("Header direction (default: both)"),
      header_name_filter: z.string().optional().describe("Filter by header name substring"),
      method_filter: z.string().optional().describe("Filter by HTTP method"),
      url_filter: z.string().optional().describe("Filter by URL substring"),
      status_filter: z.number().optional().describe("Filter by response status code"),
      hostname_filter: z.string().optional().describe("Filter by hostname substring"),
      offset: z.number().optional().default(0).describe("Offset into results (default: 0)"),
      limit: z.number().optional().default(DEFAULT_LIST_LIMIT).describe("Max fields to return (default: 50, max: 500)"),
      value_max_chars: z.number().optional().default(DEFAULT_VALUE_MAX_CHARS)
        .describe("Max characters for header value previews (default: 256)"),
    },
    async ({ target_id, direction, header_name_filter, method_filter, url_filter, status_filter, hostname_filter, offset, limit, value_max_chars }) => {
      try {
        const entry = getEntry(target_id);
        const since = entry.target.activatedAt;

        let traffic = proxyManager.getTraffic().filter((t) => t.timestamp >= since);

        if (method_filter) {
          const m = method_filter.toUpperCase();
          traffic = traffic.filter((t) => t.request.method === m);
        }
        if (url_filter) {
          const u = url_filter.toLowerCase();
          traffic = traffic.filter((t) => t.request.url.toLowerCase().includes(u));
        }
        if (status_filter !== undefined) {
          traffic = traffic.filter((t) => t.response?.statusCode === status_filter);
        }
        if (hostname_filter) {
          const h = hostname_filter.toLowerCase();
          traffic = traffic.filter((t) => t.request.hostname.toLowerCase().includes(h));
        }

        const nameNeedle = header_name_filter?.toLowerCase();
        const valueCap = Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? DEFAULT_VALUE_MAX_CHARS)));

        const rows: Array<Record<string, unknown>> = [];
        const wantReq = direction === "request" || direction === "both";
        const wantRes = direction === "response" || direction === "both";

        for (const ex of traffic) {
          if (wantReq) {
            for (const [k, v] of Object.entries(ex.request.headers)) {
              if (nameNeedle && !k.toLowerCase().includes(nameNeedle)) continue;
              const capped = capValue(v, valueCap);
              rows.push({
                field_id: `nf.${ex.id}.request.${toBase64UrlUtf8(k.toLowerCase())}`,
                exchange_id: ex.id,
                direction: "request",
                header_name: k,
                value_preview: capped.value,
                value_length: capped.valueLength,
                value_truncated: capped.truncated,
                method: ex.request.method,
                url: ex.request.url,
                hostname: ex.request.hostname,
                status: ex.response?.statusCode ?? null,
                timestamp: ex.timestamp,
              });
            }
          }
          if (wantRes && ex.response) {
            for (const [k, v] of Object.entries(ex.response.headers)) {
              if (nameNeedle && !k.toLowerCase().includes(nameNeedle)) continue;
              const capped = capValue(v, valueCap);
              rows.push({
                field_id: `nf.${ex.id}.response.${toBase64UrlUtf8(k.toLowerCase())}`,
                exchange_id: ex.id,
                direction: "response",
                header_name: k,
                value_preview: capped.value,
                value_length: capped.valueLength,
                value_truncated: capped.truncated,
                method: ex.request.method,
                url: ex.request.url,
                hostname: ex.request.hostname,
                status: ex.response.statusCode,
                timestamp: ex.timestamp,
              });
            }
          }
        }

        const total = rows.length;
        const o = normalizeOffset(offset);
        const l = normalizeLimit(limit);
        const pageRows = rows.slice(o, o + l);

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              since_ts: since,
              total,
              offset: o,
              limit: l,
              showing: pageRows.length,
              fields: pageRows,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "interceptor_browser_get_network_field",
    "Get one full header field value from proxy-captured traffic by field_id.",
    {
      target_id: z.string().describe("Target ID from interceptor_browser_launch"),
      field_id: z.string().describe("field_id from interceptor_browser_list_network_fields"),
      value_max_chars: z.number().optional().default(HARD_VALUE_CAP_CHARS)
        .describe(`Max characters for returned value (default: ${HARD_VALUE_CAP_CHARS})`),
    },
    async ({ target_id, field_id, value_max_chars }) => {
      try {
        const entry = getEntry(target_id);
        const since = entry.target.activatedAt;

        const parts = field_id.split(".");
        if (parts.length !== 4 || parts[0] !== "nf") {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid field_id '${field_id}'` }) }] };
        }
        const exchangeId = parts[1];
        const dir = parts[2];
        const headerName = fromBase64UrlUtf8(parts[3]);

        const exchange = proxyManager.getExchange(exchangeId);
        if (!exchange) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Exchange '${exchangeId}' not found in capture buffer.` }) }] };
        }
        if (exchange.timestamp < since) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "field_id refers to an exchange older than this browser session." }) }] };
        }

        let value: string | null = null;
        if (dir === "request") {
          value = exchange.request.headers[headerName.toLowerCase()] ?? null;
        } else if (dir === "response") {
          value = exchange.response?.headers?.[headerName.toLowerCase()] ?? null;
        } else {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Invalid field direction '${dir}'` }) }] };
        }
        if (value === null) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Header '${headerName}' not found on ${dir}.` }) }] };
        }

        const capped = capValue(value, Math.max(0, Math.min(HARD_VALUE_CAP_CHARS, Math.trunc(value_max_chars ?? HARD_VALUE_CAP_CHARS))));

        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              target_id,
              field_id,
              exchange_id: exchangeId,
              direction: dir,
              header_name: headerName,
              value: capped.value,
              value_length: capped.valueLength,
              value_truncated: capped.truncated,
              value_max_chars: capped.maxChars,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );
}
