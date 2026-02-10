/**
 * Utility functions for the proxy MCP server.
 */

import { networkInterfaces } from "node:os";

/**
 * Maximum characters for tool output to stay within MCP token limits.
 */
const MAX_RESULT_CHARS = 24000;

/**
 * Serialize data to JSON, truncating if it exceeds MCP limits.
 * For arrays: binary-search for max items that fit, append truncation notice.
 * For other values: slice the JSON string and append a notice.
 */
export function truncateResult(data: unknown, indent?: number): string {
  const full = JSON.stringify(data, null, indent);
  if (full.length <= MAX_RESULT_CHARS) return full;

  if (Array.isArray(data)) {
    let lo = 0;
    let hi = data.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (JSON.stringify(data.slice(0, mid), null, indent).length <= MAX_RESULT_CHARS - 200) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    const truncated = data.slice(0, lo);
    return JSON.stringify({
      items: truncated,
      truncated: true,
      showing: lo,
      total: data.length,
      message: `Showing ${lo} of ${data.length} items. Use filter/limit params to narrow results.`,
    }, null, indent);
  }

  return full.slice(0, MAX_RESULT_CHARS - 100) + "\n... [truncated, total " + full.length + " chars]";
}

/**
 * Get the first non-loopback IPv4 address for LAN proxy instructions.
 */
export function getLocalIP(): string {
  let interfaces: ReturnType<typeof networkInterfaces>;
  try {
    interfaces = networkInterfaces();
  } catch {
    return "127.0.0.1";
  }
  for (const iface of Object.values(interfaces)) {
    if (!iface) continue;
    for (const addr of iface) {
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  return "127.0.0.1";
}

/**
 * Serialize headers object to a clean record, lowercasing keys.
 */
export function serializeHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined) {
      result[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
    }
  }
  return result;
}

/**
 * Cap a string to maxLen characters, appending "..." if truncated.
 */
export function capString(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen) + "...";
}
