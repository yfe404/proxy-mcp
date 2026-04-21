/**
 * Transparent proxy tools — start/stop/status for the transparent listener.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { getLocalIP } from "../utils.js";

export function registerTransparentTools(server: McpServer): void {
  server.tool(
    "proxy_start_transparent",
    "Start the transparent proxy listener. Receives iptables-redirected traffic (no CONNECT tunnels). Shares the same CA cert, rules, and traffic buffer as the explicit proxy. The explicit proxy must be started first.",
    {
      port: z.number().optional().default(8443).describe("Port for the transparent listener (default: 8443)"),
    },
    async ({ port }) => {
      try {
        const result = await proxyManager.startTransparent(port);
        const localIP = getLocalIP();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              port: result.port,
              instructions: [
                `Transparent listener active on ${localIP}:${result.port}`,
                "Traffic will be captured in the same buffer as the explicit proxy (tagged as 'transparent')",
              ],
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_stop_transparent",
    "Stop the transparent proxy listener.",
    {},
    async () => {
      try {
        await proxyManager.stopTransparent();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: "Transparent proxy stopped." }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_transparent_status",
    "Get status of the transparent proxy listener including port and traffic count.",
    {},
    async () => {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", ...proxyManager.getTransparentStatus() }),
        }],
      };
    },
  );
}
