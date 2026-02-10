/**
 * Lifecycle tools — start/stop/status/cert for the MITM proxy.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import { getLocalIP } from "../utils.js";

export function registerLifecycleTools(server: McpServer): void {
  server.tool(
    "proxy_start",
    "Start the HTTPS MITM proxy. Auto-generates a CA certificate. Returns port, URL, cert fingerprint, and setup instructions for the target device.",
    {
      port: z.number().optional().describe("Port to listen on (0 = random available port)"),
    },
    async ({ port }) => {
      try {
        const result = await proxyManager.start(port);
        const localIP = getLocalIP();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              port: result.port,
              url: result.url,
              certFingerprint: result.cert.fingerprint,
              setup: {
                proxyHost: localIP,
                proxyPort: result.port,
                instructions: [
                  `1. Set device Wi-Fi proxy to ${localIP}:${result.port}`,
                  "2. Install the CA certificate on the device (use proxy_get_ca_cert)",
                  `3. Or use env vars: HTTP_PROXY=http://${localIP}:${result.port} HTTPS_PROXY=http://${localIP}:${result.port}`,
                ],
              },
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_stop",
    "Stop the MITM proxy. Traffic history and CA certificate are retained.",
    {},
    async () => {
      try {
        await proxyManager.stop();
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: "Proxy stopped. Traffic and cert retained." }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_status",
    "Get proxy running state, port, upstream config, rule count, and traffic count.",
    {},
    async () => {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", ...proxyManager.getStatus() }),
        }],
      };
    },
  );

  server.tool(
    "proxy_get_ca_cert",
    "Get the CA certificate PEM and SPKI fingerprint for installing on the target device.",
    {
      format: z.enum(["pem", "fingerprint", "both"]).optional().default("both")
        .describe("What to return: 'pem', 'fingerprint', or 'both'"),
    },
    async ({ format }) => {
      const cert = proxyManager.getCert();
      if (!cert) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "No certificate. Start the proxy first." }) }] };
      }

      const result: Record<string, unknown> = { status: "success" };
      if (format === "pem" || format === "both") {
        result.certPem = cert.cert;
      }
      if (format === "fingerprint" || format === "both") {
        result.fingerprint = cert.fingerprint;
      }
      result.instructions = "Save the PEM to a .crt file, transfer to device, and install as trusted CA.";

      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    },
  );
}
