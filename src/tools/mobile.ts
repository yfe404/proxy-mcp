/**
 * One-command mobile-capture orchestrator.
 *
 * proxy_mobile_setup: detect USB iface → start explicit + transparent listeners
 * → emit a sudo-runnable script with iptables + sysctl + nmcli → inject CA on
 * an Android device via the existing AndroidAdbInterceptor.
 *
 * proxy_mobile_teardown: reverse operation — emit sudo script to drop rules,
 * deactivate Android target, stop both listeners.
 *
 * MCP runs as the invoking user; iptables requires root, so the tool emits a
 * script and returns its path rather than executing it directly. Caller runs
 * `sudo bash <path>` once. Keeps everything auditable and distro-portable.
 *
 * Pairs with the `proxy-ap-card` firmware (XIAO ESP32-S3 rogue AP presenting
 * as USB NCM): the card handles WiFi + NAPT, this tool wires the laptop side.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { proxyManager } from "../state.js";
import { interceptorManager } from "../interceptors/manager.js";

function errorToString(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/** Return the driver name for a given interface via /sys, or null. */
function ifaceDriver(iface: string): string | null {
  try {
    const link = readFileSync(`/sys/class/net/${iface}/device/uevent`, "utf8");
    const m = link.match(/DRIVER=(\S+)/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/** Auto-detect USB-ethernet-to-proxy-ap-card interface. */
function detectApIface(): { iface: string; reason: string } | null {
  let netIfaces: string[];
  try {
    netIfaces = readdirSync("/sys/class/net");
  } catch {
    return null;
  }
  // Priority 1: cdc_ncm driver (what the proxy-ap-card firmware presents as)
  for (const name of netIfaces) {
    if (ifaceDriver(name) === "cdc_ncm") {
      return { iface: name, reason: "driver=cdc_ncm (proxy-ap-card default)" };
    }
  }
  // Priority 2: cdc_ether (alternative CDC Ethernet class)
  for (const name of netIfaces) {
    if (ifaceDriver(name) === "cdc_ether") {
      return { iface: name, reason: "driver=cdc_ether" };
    }
  }
  return null;
}

/** Detect host's default internet-facing interface. */
function detectEgressIface(): string {
  try {
    const routes = readFileSync("/proc/net/route", "utf8").split("\n").slice(1);
    for (const line of routes) {
      const parts = line.split("\t");
      if (parts.length < 2) continue;
      if (parts[1] === "00000000") return parts[0]; // default route
    }
  } catch { /* fall through */ }
  return "eth0";
}

function buildSetupScript(opts: {
  apIface: string;
  apSubnet: string;
  apAddress: string;
  egressIface: string;
  explicitPort: number;
  transparentPort: number;
  blockQuic: boolean;
}): string {
  return `#!/bin/bash
# proxy-mcp mobile capture — apply host-side network rules.
# Safe to re-run: rules are idempotent (-C checks before -A).
set -euo pipefail

AP_IFACE="${opts.apIface}"
AP_ADDR="${opts.apAddress}"
AP_SUBNET="${opts.apSubnet}"
EGRESS_IFACE="${opts.egressIface}"
HTTP_PORT="${opts.explicitPort}"
HTTPS_PORT="${opts.transparentPort}"

echo "AP iface       : \$AP_IFACE"
echo "AP address     : \$AP_ADDR"
echo "Egress iface   : \$EGRESS_IFACE"
echo "proxy-mcp HTTP : :\$HTTP_PORT"
echo "proxy-mcp HTTPS: :\$HTTPS_PORT (transparent)"
echo

# Let proxy-mcp manage the iface — unhook NetworkManager if it's attached.
nmcli device set "\$AP_IFACE" managed no 2>/dev/null || true

# Assign a static address if one isn't set. Skipped if already configured.
if ! ip -o -4 addr show dev "\$AP_IFACE" | grep -qw "\$AP_ADDR"; then
  ip link set "\$AP_IFACE" up
  ip addr flush dev "\$AP_IFACE"
  ip addr add "\$AP_ADDR" dev "\$AP_IFACE"
fi

# IP forwarding on.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Fresh dedicated chain so rules are easy to flush.
iptables -t nat -F PROXY_MCP_PREROUTING 2>/dev/null || true
iptables -t nat -X PROXY_MCP_PREROUTING 2>/dev/null || true
iptables -t nat -N PROXY_MCP_PREROUTING
# HTTP → proxy-mcp explicit listener (handles absolute-URL HTTP requests).
iptables -t nat -A PROXY_MCP_PREROUTING -p tcp --dport 80  -j REDIRECT --to-ports "\$HTTP_PORT"
# HTTPS → proxy-mcp transparent listener (SNI-based MITM, no CONNECT needed).
iptables -t nat -A PROXY_MCP_PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports "\$HTTPS_PORT"

# Hook on the AP iface only.
iptables -t nat -C PREROUTING -i "\$AP_IFACE" -j PROXY_MCP_PREROUTING 2>/dev/null \\
  || iptables -t nat -A PREROUTING -i "\$AP_IFACE" -j PROXY_MCP_PREROUTING

${opts.blockQuic
  ? `# Block QUIC on the AP iface so apps fall back to TCP/TLS (capturable).
iptables -C FORWARD -i "\$AP_IFACE" -p udp --dport 443 -j DROP 2>/dev/null \\
  || iptables -A FORWARD -i "\$AP_IFACE" -p udp --dport 443 -j DROP
`
  : "# QUIC forwarding left intact (will not be captured by the transparent listener).\n"
}
# Masquerade out through the real egress.
iptables -t nat -C POSTROUTING -s "\$AP_SUBNET" -o "\$EGRESS_IFACE" -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -s "\$AP_SUBNET" -o "\$EGRESS_IFACE" -j MASQUERADE

echo
echo "Done. Connect the target device to the proxy-ap WiFi — traffic will flow"
echo "through proxy-mcp on ports \$HTTP_PORT (HTTP) and \$HTTPS_PORT (HTTPS)."
`;
}

function buildTeardownScript(opts: {
  apIface: string;
  apSubnet: string;
  egressIface: string;
  blockQuic: boolean;
}): string {
  return `#!/bin/bash
# proxy-mcp mobile capture — remove host-side network rules.
set -u

AP_IFACE="${opts.apIface}"
AP_SUBNET="${opts.apSubnet}"
EGRESS_IFACE="${opts.egressIface}"

iptables -t nat -D PREROUTING -i "\$AP_IFACE" -j PROXY_MCP_PREROUTING 2>/dev/null || true
iptables -t nat -F PROXY_MCP_PREROUTING 2>/dev/null || true
iptables -t nat -X PROXY_MCP_PREROUTING 2>/dev/null || true
${opts.blockQuic
  ? `iptables -D FORWARD -i "\$AP_IFACE" -p udp --dport 443 -j DROP 2>/dev/null || true\n`
  : ""}iptables -t nat -D POSTROUTING -s "\$AP_SUBNET" -o "\$EGRESS_IFACE" -j MASQUERADE 2>/dev/null || true

sysctl -w net.ipv4.ip_forward=0 >/dev/null

ip addr flush dev "\$AP_IFACE" 2>/dev/null || true
nmcli device set "\$AP_IFACE" managed yes 2>/dev/null || true

echo "Teardown complete."
`;
}

function writeScript(content: string, suffix: string): string {
  const name = `proxy-mcp-${suffix}-${randomBytes(4).toString("hex")}.sh`;
  const path = join(tmpdir(), name);
  writeFileSync(path, content, "utf8");
  chmodSync(path, 0o755);
  return path;
}

export function registerMobileTools(server: McpServer): void {
  server.tool(
    "proxy_mobile_setup",
    "One-command mobile capture: start explicit + transparent listeners, optionally inject the CA on an Android device, and emit a sudo-runnable script that wires iptables/sysctl/nmcli on the AP iface. Designed to pair with the proxy-ap-card firmware (ESP32-S3 rogue AP over USB-NCM).",
    {
      ap_iface: z.string().optional().describe("AP/USB interface name. Auto-detected via cdc_ncm driver if omitted."),
      ap_address: z.string().optional().default("192.168.99.2/24").describe("Laptop-side address on the AP iface (default: 192.168.99.2/24, matches proxy-ap-card firmware)."),
      ap_subnet: z.string().optional().default("192.168.4.0/24").describe("Subnet the AP serves to clients (default: 192.168.4.0/24, matches proxy-ap-card firmware)."),
      egress_iface: z.string().optional().describe("Host's internet-facing iface. Auto-detected from /proc/net/route if omitted."),
      explicit_port: z.number().optional().default(8080).describe("Port for the explicit HTTP proxy (default: 8080)."),
      transparent_port: z.number().optional().default(8443).describe("Port for the transparent HTTPS listener (default: 8443)."),
      block_quic: z.boolean().optional().default(true).describe("Drop UDP/443 on the AP iface so apps fall back to TCP/TLS (capturable). Default: true."),
      upstream_proxy_url: z.string().optional().describe("Optional upstream proxy URL (socks5://user:pass@host:port or http://...). Sets the global upstream for BOTH listeners."),
      android_serial: z.string().optional().describe("ADB serial of an Android device to inject the CA on. If omitted, no cert injection is attempted."),
      inject_cert: z.boolean().optional().default(true).describe("Inject the CA into the Android device's system store. Ignored if android_serial is omitted."),
    },
    async ({
      ap_iface,
      ap_address,
      ap_subnet,
      egress_iface,
      explicit_port,
      transparent_port,
      block_quic,
      upstream_proxy_url,
      android_serial,
      inject_cert,
    }) => {
      try {
        // 1. Resolve AP iface.
        let apIface = ap_iface;
        let ifaceReason = "user-provided";
        if (!apIface) {
          const detected = detectApIface();
          if (!detected) {
            return { content: [{ type: "text", text: JSON.stringify({
              status: "error",
              error: "Could not auto-detect an AP interface. Plug in the proxy-ap-card (or another cdc_ncm USB NCM device) and retry, or pass ap_iface explicitly. Known interfaces:",
              interfaces: readdirSync("/sys/class/net").filter((n) => n !== "lo"),
            }) }] };
          }
          apIface = detected.iface;
          ifaceReason = detected.reason;
        }

        // 2. Resolve egress.
        const egressIface = egress_iface ?? detectEgressIface();

        // 3. Explicit proxy.
        let explicitPortUsed = explicit_port;
        if (!proxyManager.isRunning()) {
          const started = await proxyManager.start(explicit_port);
          explicitPortUsed = started.port;
        } else {
          explicitPortUsed = proxyManager.getPort() ?? explicit_port;
        }

        // 4. Transparent listener.
        let transparentPortUsed = transparent_port;
        if (!proxyManager.isTransparentRunning()) {
          const startedTp = await proxyManager.startTransparent(transparent_port);
          transparentPortUsed = startedTp.port;
        } else {
          transparentPortUsed = proxyManager.getTransparentPort() ?? transparent_port;
        }

        // 5. Upstream (optional).
        let upstreamSet = false;
        if (upstream_proxy_url) {
          await proxyManager.setGlobalUpstream({ proxyUrl: upstream_proxy_url });
          upstreamSet = true;
        }

        // 6. Android CA injection (optional).
        let certInjected = false;
        let androidTargetId: string | null = null;
        if (android_serial && inject_cert) {
          const cert = proxyManager.getCert();
          if (!cert) throw new Error("Proxy started but no cert was generated — this is a bug.");
          const result = await interceptorManager.activate("android-adb", {
            proxyPort: explicitPortUsed,
            certPem: cert.cert,
            certFingerprint: cert.fingerprint,
            serial: android_serial,
            injectCert: true,
            setupTunnel: false,  // AP + iptables handle routing; no reverse tunnel needed
            setWifiProxy: false, // same reason
          });
          certInjected = true;
          androidTargetId = result.targetId;
        }

        // 7. Emit sudo script.
        const scriptPath = writeScript(
          buildSetupScript({
            apIface,
            apAddress: ap_address,
            apSubnet: ap_subnet,
            egressIface,
            explicitPort: explicitPortUsed,
            transparentPort: transparentPortUsed,
            blockQuic: block_quic,
          }),
          "mobile-setup",
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              ap_iface: apIface,
              ap_iface_reason: ifaceReason,
              ap_address,
              ap_subnet,
              egress_iface: egressIface,
              explicit_port: explicitPortUsed,
              transparent_port: transparentPortUsed,
              block_quic,
              upstream_set: upstreamSet,
              cert_injected: certInjected,
              android_target_id: androidTargetId,
              sudo_script: scriptPath,
              sudo_command: `sudo bash ${scriptPath}`,
              next_steps: [
                `Run:  sudo bash ${scriptPath}`,
                "Connect the target device to the proxy-ap WiFi network (credentials live in the proxy-ap-card firmware).",
                "Call proxy_list_traffic — transparent HTTPS exchanges appear with source=\"transparent\", HTTP with source=\"explicit\".",
                "When done, call proxy_mobile_teardown and run the emitted sudo script.",
              ],
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_mobile_teardown",
    "Reverse proxy_mobile_setup: deactivate the Android target if any, stop the transparent + explicit listeners, and emit a sudo-runnable script that removes the iptables rules and restores NetworkManager management.",
    {
      ap_iface: z.string().optional().describe("AP/USB interface name. Auto-detected via cdc_ncm if omitted."),
      ap_subnet: z.string().optional().default("192.168.4.0/24").describe("Subnet the AP serves (must match setup)."),
      egress_iface: z.string().optional().describe("Host's egress iface (must match setup)."),
      block_quic: z.boolean().optional().default(true).describe("Whether the QUIC DROP rule was set up (so we know to remove it)."),
      android_target_id: z.string().optional().describe("Android target ID to deactivate (from proxy_mobile_setup response)."),
      stop_proxy: z.boolean().optional().default(false).describe("Also stop the explicit proxy (default: keep it running for continued use)."),
    },
    async ({ ap_iface, ap_subnet, egress_iface, block_quic, android_target_id, stop_proxy }) => {
      try {
        let apIface = ap_iface;
        if (!apIface) {
          const detected = detectApIface();
          if (!detected) {
            return { content: [{ type: "text", text: JSON.stringify({
              status: "error",
              error: "Could not auto-detect AP iface for teardown. Pass ap_iface explicitly.",
            }) }] };
          }
          apIface = detected.iface;
        }
        const egressIface = egress_iface ?? detectEgressIface();

        if (android_target_id) {
          await interceptorManager.deactivate("android-adb", android_target_id).catch(() => {});
        }
        if (proxyManager.isTransparentRunning()) {
          await proxyManager.stopTransparent().catch(() => {});
        }
        if (stop_proxy && proxyManager.isRunning()) {
          await proxyManager.stop().catch(() => {});
        }

        const scriptPath = writeScript(
          buildTeardownScript({
            apIface,
            apSubnet: ap_subnet,
            egressIface,
            blockQuic: block_quic,
          }),
          "mobile-teardown",
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              ap_iface: apIface,
              egress_iface: egressIface,
              android_target_deactivated: !!android_target_id,
              transparent_stopped: true,
              explicit_stopped: stop_proxy,
              sudo_script: scriptPath,
              sudo_command: `sudo bash ${scriptPath}`,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_mobile_detect_iface",
    "Auto-detect the USB-NCM interface the proxy-ap-card presents as (via the cdc_ncm driver). Returns null + iface list if none found.",
    {},
    async () => {
      try {
        const detected = detectApIface();
        if (!detected) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "success",
                found: false,
                interfaces: readdirSync("/sys/class/net").filter((n) => n !== "lo"),
              }),
            }],
          };
        }
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              found: true,
              iface: detected.iface,
              reason: detected.reason,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: errorToString(e) }) }] };
      }
    },
  );
}
