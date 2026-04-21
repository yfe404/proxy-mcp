# proxy-mcp

proxy-mcp is an MCP server that runs an explicit HTTP/HTTPS MITM proxy (L7). It captures requests/responses, lets you modify traffic in-flight (headers/bodies/mock/forward/drop), supports upstream proxy chaining, and records TLS fingerprints for connections to the proxy (JA3/JA4) plus optional upstream server JA3S. Ships "interceptors" to route a stealth browser (cloakbrowser, source-patched Chromium), CLI tools, Docker containers, and Android devices/apps through the proxy, plus Playwright-driven browser automation with locator-based click, typing, scroll, and ARIA snapshots.

71 tools + 6 resources + 3 resource templates. Built on [mockttp](https://github.com/httptoolkit/mockttp) and [cloakbrowser](https://cloakbrowser.dev/).

## Table of Contents

- [Setup](#setup)
- [HTTP Proxy Configuration](#http-proxy-configuration)
- [Boundaries](#boundaries)
- [TLS ClientHello Passthrough](#tls-clienthello-passthrough-chrome-via-interceptor)
- [Pairs well with CDP/Playwright](#pairs-well-with-cdpplaywright)
- [Mobile Capture (Transparent Proxy)](#mobile-capture-transparent-proxy)
- [Tools Reference](#tools-reference)
  - [Lifecycle](#lifecycle-4)
  - [Upstream Proxy](#upstream-proxy-4)
  - [Interception Rules](#interception-rules-7)
  - [Traffic Capture](#traffic-capture-4)
  - [Modification Shortcuts](#modification-shortcuts-3)
  - [TLS Fingerprinting](#tls-fingerprinting-9)
  - [Interceptors](#interceptors-17)
  - [Browser DevTools-equivalents](#browser-devtools-equivalents-9)
  - [Sessions](#sessions-13)
  - [Humanizer](#humanizer--playwright-input-5)
- [Resources](#resources)
- [Usage Example](#usage-example)
- [Architecture](#architecture)
- [Testing](#testing)
- [Credits](#credits)

## Setup

### Quick install (Claude Code)

```bash
claude mcp add proxy-mcp -- npx -y proxy-mcp@latest
```

This installs proxy-mcp as an MCP server using stdio transport. It auto-updates on every Claude Code restart.

**Scopes:**

```bash
# Per-user (available in all projects)
claude mcp add --scope user proxy-mcp -- npx -y proxy-mcp@latest

# Per-project (shared via .mcp.json, commit to repo)
claude mcp add --scope project proxy-mcp -- npx -y proxy-mcp@latest
```

### Prerequisites

- Node.js 22+

### From source (development)

```bash
git clone https://github.com/yfe404/proxy-mcp.git
cd proxy-mcp
npm install
npm run build
```

```bash
# stdio transport (default) — used by MCP clients like Claude Code
node dist/index.js

# Streamable HTTP transport — exposes /mcp endpoint for scripting
node dist/index.js --transport http --port 3001
```

`--transport` and `--port` also accept env vars `TRANSPORT` and `PORT`.

### Manual MCP configuration

**Claude Code CLI:**

```bash
# stdio (default)
claude mcp add proxy-mcp -- npx -y proxy-mcp@latest

# From local clone
claude mcp add proxy-mcp -- node /path/to/proxy-mcp/dist/index.js

# HTTP transport for scripting
claude mcp add --transport http proxy-mcp http://127.0.0.1:3001/mcp
```

**`.mcp.json` (project-level, commit to repo):**

```json
{
  "mcpServers": {
    "proxy": {
      "command": "npx",
      "args": ["-y", "proxy-mcp@latest"]
    }
  }
}
```

**Streamable HTTP transport:**

```json
{
  "mcpServers": {
    "proxy": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:3001/mcp"
    }
  }
}
```

## HTTP Proxy Configuration

### 1) Start proxy and get endpoint

```bash
proxy_start
```

Use the returned `port` and endpoint `http://127.0.0.1:<port>`.

### 2) Browser setup (recommended: interceptor)

Use the browser interceptor so proxy flags and cert trust are configured automatically. Launches [cloakbrowser](https://cloakbrowser.dev/) — a stealth-patched Chromium with source-level C++ fingerprint patches and humanize mode on by default:

```bash
interceptor_browser_launch --url "https://example.com"
```

Drive the page with Playwright-backed tools (no CDP, no sidecar — `target_id` is all you need):

```bash
interceptor_browser_navigate --target_id "browser_<id>" --url "https://apify.com"
interceptor_browser_snapshot  --target_id "browser_<id>"
interceptor_browser_screenshot --target_id "browser_<id>" --file_path "/tmp/shot.png"
```

### 3) Browser setup (manual fallback)

If launching a browser manually, pass the proxy flag yourself:

```bash
google-chrome --proxy-server="http://127.0.0.1:<port>"
```

### 4) CLI/process setup

Route any process through proxy-mcp by setting proxy env vars:

```bash
export HTTP_PROXY="http://127.0.0.1:<port>"
export HTTPS_PROXY="http://127.0.0.1:<port>"
export NO_PROXY="localhost,127.0.0.1"
```

If the client verifies TLS, trust the proxy-mcp CA certificate (see `proxy_get_ca_cert`) or use the Terminal interceptor (`interceptor_spawn`) which sets proxy env vars plus common CA env vars (curl, Node, Python requests, Git, npm/yarn, etc.):

```bash
interceptor_spawn --command curl --args '["-s","https://example.com"]'
```

Explicit `curl` examples:

```bash
curl --proxy http://127.0.0.1:<port> http://example.com
curl --proxy http://127.0.0.1:<port> https://example.com
```

### 5) Upstream proxy chaining

Set optional proxy chaining from proxy-mcp to another upstream proxy (for geolocation, auth, or IP reputation):

```
Client/app  →  proxy-mcp (local explicit proxy)  →  upstream proxy (optional chaining layer)
```

```bash
proxy_set_upstream --proxy_url "socks5://user:pass@upstream.example:1080"
```

Supported upstream URL schemes: `socks4://`, `socks5://`, `http://`, `https://`, `pac+http://`.

Typical geo-routing examples:

```bash
# Route ALL outgoing traffic from proxy-mcp via a geo proxy
proxy_set_upstream --proxy_url "socks5://user:pass@fr-exit.example.net:1080"

# Bypass upstream for local/internal hosts
proxy_set_upstream --proxy_url "http://user:pass@proxy.example.net:8080" --no_proxy '["localhost","127.0.0.1",".corp.local"]'

# Route only one hostname via a dedicated upstream (overrides global)
proxy_set_host_upstream --hostname "api.example.com" --proxy_url "https://user:pass@us-exit.example.net:443"

# Remove overrides when done
proxy_remove_host_upstream --hostname "api.example.com"
proxy_clear_upstream
```

For HTTPS MITM, the proxy CA must be trusted in the target environment (`proxy_get_ca_cert`).

### 6) Validate and troubleshoot quickly

```bash
proxy_list_traffic --limit 20
proxy_search_traffic --query "example.com"
```

Common issues:
- Traffic from the wrong browser instance (fix: always pass `target_id` from `interceptor_browser_launch`)
- HTTPS cert trust missing on target
- `NO_PROXY` bypassing expected hosts
- First launch is slow: cloakbrowser downloads a ~200 MB stealth Chromium binary on first use (cached afterwards)

### 7) HAR import + replay

Import HAR into a persisted session, then analyze with existing session query/findings tools:

```bash
proxy_import_har --har_file "/path/to/capture.har" --session_name "imported-run"
proxy_list_sessions
proxy_query_session --session_id SESSION_ID --hostname_contains "api.example.com"
proxy_get_session_handshakes --session_id SESSION_ID
```

Replay defaults to dry-run (preview only). Execute requires explicit mode:

```bash
# Preview what would be replayed
proxy_replay_session --session_id SESSION_ID --mode dry_run --limit 20

# Execute replay against original hosts
proxy_replay_session --session_id SESSION_ID --mode execute --limit 20

# Optional: override target host/base URL while preserving path+query
proxy_replay_session --session_id SESSION_ID --mode execute --target_base_url "http://127.0.0.1:8081"
```

Note: imported HAR entries (and entries created by `proxy_replay_session`) do not carry JA3/JA4/JA3S handshake metadata. Use live proxy-captured traffic to analyze handshake fingerprints.

## Mobile Capture (Transparent Proxy)

For mobile apps with custom HTTP stacks that ignore the system proxy (most modern Android apps — Shopee, SHEIN, TikTok, banking, etc.) the explicit proxy won't see their traffic. proxy-mcp ships a **transparent listener** that sits behind an iptables REDIRECT and MITMs using the TLS SNI — no CONNECT tunnel required.

Pairs with [proxy-ap-card](https://github.com/yfe404/proxy-ap-card) — a XIAO ESP32-S3 that broadcasts a WiFi AP (`proxy-ap` SSID by default) and presents to the laptop as a USB-NCM ethernet adapter. That repo handles the AP + NAPT side; proxy-mcp handles the laptop side.

### Prerequisites

- **Laptop**: Linux with `iptables`, `sysctl`, `nmcli` (NetworkManager), `ip` (iproute2), `adb`. `sudo` for network configuration (one command per session).
- **Hardware router**: a [proxy-ap-card](https://github.com/yfe404/proxy-ap-card) (XIAO ESP32-S3) with firmware flashed. Or any USB-ethernet / USB-WiFi combo where the laptop NATs traffic for the phone's subnet — pass `--ap_iface` / `--ap_subnet` to override defaults.
- **Target device**: Android with **root** (Magisk / KernelSU). Root is required to inject the CA into the system cert store. Android 14-16 additionally need the zygote mount-namespace injection which this tool does automatically.
- **ADB access**: the target device must appear in `adb devices` (USB at minimum, wireless after pairing).

### First-time walkthrough

#### 1. Flash + plug in the proxy-ap-card

Follow the [proxy-ap-card README](https://github.com/yfe404/proxy-ap-card) to build + flash the XIAO. On replug the laptop should show a `cdc_ncm` interface (verify: `ls /sys/class/net/*/device/uevent | xargs grep DRIVER | grep cdc_ncm`).

#### 2. Connect the target device to the laptop via USB

Only needed the first time per device, to push the CA. Verify with `adb devices`. Copy the serial.

#### 3. Run the setup tool

```
proxy_mobile_setup --android_serial <serial>
```

Optional arguments:

| Param | Default | When to override |
|-------|---------|------------------|
| `ap_iface` | auto-detect (`cdc_ncm`) | Using a different USB-ethernet bridge |
| `ap_address` | `192.168.99.2/24` | Matches default proxy-ap-card firmware |
| `ap_subnet` | `192.168.4.0/24` | Matches default proxy-ap-card firmware |
| `egress_iface` | auto-detect from default route | Multi-homed host, or wanting traffic to exit via a specific iface |
| `explicit_port` | `8080` | Port collision |
| `transparent_port` | `8443` | Port collision |
| `block_quic` | `true` | Need QUIC/HTTP3 (no MITM available then) |
| `upstream_proxy_url` | — | Route outbound through a residential/ISP proxy — see below |
| `android_serial` | — | Omit to skip CA injection (remote-only setups) |
| `inject_cert` | `true` if `android_serial` set | Set `false` to re-use a prior install |

The response is JSON with three key bits:

```json
{
  "ap_iface": "enp195s0f3u1u4",
  "cert_injected": true,
  "android_target_id": "adb_HQ63C81CB2",
  "sudo_command": "sudo bash /tmp/proxy-mcp-mobile-setup-<hex>.sh"
}
```

Keep `android_target_id` around — you'll need it for teardown.

#### 4. Run the emitted sudo script

```
sudo bash /tmp/proxy-mcp-mobile-setup-<hex>.sh
```

This is the only sudo required. The script is idempotent, safe to re-run. It plumbs the routing that `iptables` needs root for:

```bash
# Static IP on the AP iface (skipped if already configured).
ip addr add 192.168.99.2/24 dev <ap_iface>

# Forwarding + dedicated nat chain.
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -N PROXY_MCP_PREROUTING
iptables -t nat -A PROXY_MCP_PREROUTING -p tcp --dport 80  -j REDIRECT --to-ports 8080
iptables -t nat -A PROXY_MCP_PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
iptables -t nat -A PREROUTING -i <ap_iface> -j PROXY_MCP_PREROUTING

# Block QUIC so apps fall back to TCP/TLS.
iptables -A FORWARD -i <ap_iface> -p udp --dport 443 -j DROP

# Masquerade out through the real egress.
iptables -t nat -A POSTROUTING -s 192.168.4.0/24 -o <egress_iface> -j MASQUERADE
```

Why a script and not direct execution? MCP runs as your user; iptables needs root; `sudo` from an MCP tool would require NOPASSWD or polkit policy (fragile, distro-specific). Emitting a script is auditable, reproducible, and portable.

#### 5. Connect the phone to the `proxy-ap` WiFi

Credentials are set in the proxy-ap-card firmware (default SSID `proxy-ap`, default password shown in that repo). After connecting, the phone can be unplugged from USB — future sessions don't need it.

#### 6. Start capturing

Every HTTP/HTTPS request from the phone now lands in proxy-mcp's ring buffer:

```
proxy_list_traffic --source_filter transparent   # iptables-redirected HTTPS
proxy_list_traffic --source_filter explicit      # absolute-URL HTTP that arrived on :80
proxy_get_exchange --exchange_id <id>            # full headers + body preview
proxy_search_traffic --query "api.example.com"   # full-text search
```

Each entry carries `source: "explicit" | "transparent"` + TLS fingerprints (`ja3`, `ja4`).

### Subsequent sessions (phone already paired)

Skip step 2. Run:

```
proxy_mobile_setup                                # skip android_serial — cert already installed
sudo bash /tmp/proxy-mcp-mobile-setup-<hex>.sh
```

Then phone joins the AP and capture resumes.

### Upstream chaining

Set `upstream_proxy_url` to route outbound traffic through a residential/ISP proxy — the target servers see that proxy's IP, not your laptop's:

```
proxy_mobile_setup \
  --upstream_proxy_url "http://user:pass@proxy.example.com:8000" \
  --android_serial <serial>
```

Applies to BOTH listeners. Use `proxy_set_upstream` after the fact to change it without restarting.

### Verifying each step

| Check | Command | Expected |
|-------|---------|----------|
| Listeners up | `proxy_status` | `running: true`, `transparentProxy.running: true` |
| Iface detected | `proxy_mobile_detect_iface` | `found: true`, iface name |
| Cert injected | `adb shell "su -c 'nsenter --mount=/proc/\$(pidof zygote64)/ns/mnt -- ls /apex/com.android.conscrypt/cacerts/ \| wc -l'"` | 144 (or 143 + 1) |
| iptables wired | `sudo iptables -t nat -L PROXY_MCP_PREROUTING -v -n` | 2 REDIRECT rules, non-zero `pkts` after phone generates traffic |
| Forwarding on | `cat /proc/sys/net/ipv4/ip_forward` | `1` |
| Phone sees AP | phone Settings → WiFi shows `proxy-ap` connected, IP in `192.168.4.0/24` |
| Traffic flowing | `proxy_list_traffic --limit 5` after opening any app | `source: "transparent"` entries with status 200 |

### Teardown

```
proxy_mobile_teardown --android_target_id <from-setup>
sudo bash /tmp/proxy-mcp-mobile-teardown-<hex>.sh
```

The MCP call stops both listeners and deactivates the Android target. The sudo script removes the iptables rules, disables `ip_forward`, and hands the AP iface back to NetworkManager. Phone stays connected to the AP until you forget it in phone WiFi settings.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `proxy_mobile_detect_iface` returns `found: false` | proxy-ap-card not plugged in, or `cdc_ncm` driver missing | `lsusb \| grep '303a:'`; `dmesg \| grep cdc_ncm`; re-plug the card |
| `setup` errors `No such file or directory: /sys/class/net/.../device/uevent` | iface name passed explicitly but doesn't exist | Use auto-detect or verify with `ip link` |
| Phone connects to AP but zero traffic in `proxy_list_traffic` | sudo script not run; or phone on a different WiFi | Verify `cat /proc/sys/net/ipv4/ip_forward` returns `1`; check phone's active SSID |
| Phone says "no internet" on `proxy-ap` | Forward + MASQUERADE rules missing, OR egress iface down | Re-run the sudo script; check `ip route show default` |
| HTTPS fails with "connection not private" or similar | Cert not trusted by the app (Chrome bundles its own CAs and ignores system trust, app has cert pinning) | Use another app to verify chain works; Chrome is the exception not the rule (see limitations below) |
| Some apps capture, others don't | Cert pinning in the apps that fail | See limitations below; Frida/LSPosed unpinning module needed |
| Ports 20346/20443/other custom ports not captured | Only `:80` and `:443` are redirected | Add extra REDIRECT rules in the sudo script, or pair redsocks to `CONNECT`-tunnel arbitrary ports through the explicit listener |
| `cert_injected: false` or zygote `nsenter` failed | Device not rooted, or SELinux `chcon` rejected | `adb shell su -c 'id'` must return `uid=0`; confirm `zygisksu` / Magisk is active |
| Wireless ADB port changes every session | Android's Wireless Debugging randomises the port | Re-pair; or keep phone plugged in for control plane |

### Without the proxy-ap-card

Any USB-NCM or USB-ethernet bridge that the phone can route through works:

```
proxy_mobile_setup --ap_iface eth1 --ap_address 10.0.0.1/24 --ap_subnet 10.0.0.0/24
```

Or use a laptop-hosted WiFi AP via `hostapd` on a USB WiFi adapter (MT76x2U, RTL8812AU, etc.) — pass the `wlanN` interface as `ap_iface`.

### Limitations

- **Cert pinning** — apps that pin specific public keys (Instagram, WhatsApp, banking, Shopee homepage feed, etc.) will refuse our mockttp cert even with CA trust installed. You see partial capture (tracking / static / unpinned endpoints succeed, pinned API calls fail). Fix: Frida or LSPosed unpinning module for that specific app. See `interceptor_frida_attach` in the tool reference, or [morrownr's USB-WiFi guides](https://github.com/morrownr/USB-WiFi) for common patterns.
- **Chrome on Android** — Chrome ships its own Mozilla CA bundle and enforces Certificate Transparency. Our CA is self-signed and not in any CT log, so Chrome rejects it regardless of system trust. Use any other app (or any OkHttp/Conscrypt-based browser) to verify the pipeline.
- **QUIC / HTTP3** — the transparent listener is TCP/TLS only. By default we drop UDP/443 so apps fall back to TCP. Set `block_quic: false` if you *want* QUIC to pass through uncaptured (QUIC content won't appear in traffic logs).
- **Non-standard ports** — the default iptables rules only redirect TCP/80 and TCP/443. Shopee's `:20346`, custom gaming protocols, etc. will bypass. Add more REDIRECT rules in the sudo script (or chain `redsocks` to issue CONNECT tunnels through the explicit listener).
- **Native TLS pinning** — some apps use BoringSSL/OpenSSL directly via JNI with pins embedded in the `.so`. Java-layer Frida hooks won't catch these; native hooks needed.
- **Root required** — the system-trust CA overlay requires root. Non-rooted Android only trusts user-installed CAs for apps that explicitly opt in via `network_security_config` — which no shipping app does. There's no bypass for that without root.

## Boundaries

- Only sees traffic **configured to route through it** (not a network tap or packet sniffer)
- Spoofs **outgoing JA3 + HTTP/2 fingerprint + header order** (via impit — native Rust TLS impersonation), not JA4 (JA4 is capture-only)
- Can add, overwrite, or delete HTTP headers; outgoing header **order** can be controlled via fingerprint spoofing
- Returns its own CA certificate — does **not** expose upstream server certificate chains

### TLS ClientHello Passthrough (browser via interceptor)

When cloakbrowser is launched via `interceptor_browser_launch`, proxy-mcp forwards the browser's **original TLS ClientHello** to the upstream server for document loads and same-origin sub-resource requests. The target server sees an authentic Chrome TLS fingerprint — not the proxy's.

This is a key difference from typical MITM proxies (mitmproxy, Charles, Fiddler) which re-terminate TLS with their own fingerprint, making MITM trivially detectable by anti-bot systems via JA3/JA4 analysis.

**How to verify passthrough is working:**

```bash
proxy_list_tls_fingerprints --hostname_filter "example.com"
```

- **JA3 varies** across requests to the same host — this is expected; Chrome randomizes cipher suite order per-connection (feature since Chrome 110+)
- **JA4 stays stable** — same cipher/extension set, just different ordering
- JA3 variation + JA4 stability = authentic Chrome TLS passthrough confirmed

**When passthrough applies vs. when spoofing is needed:**

| Traffic source | TLS behavior | Action needed |
|---|---|---|
| cloakbrowser via `interceptor_browser_launch` (document loads, same-origin) | Browser's native ClientHello forwarded (passthrough) | None — fingerprint is authentic |
| cloakbrowser via `interceptor_browser_launch` (cross-origin sub-resources, when spoof active) | Re-issued via impit with spoofed TLS | `proxy_set_fingerprint_spoof` with a browser preset |
| Non-browser clients (curl, Python, `interceptor_spawn`) | Proxy's own TLS | `proxy_set_fingerprint_spoof` or `proxy_set_ja3_spoof` required |
| HAR replay (`proxy_replay_session`) | Proxy's own TLS | `proxy_set_fingerprint_spoof` required |

### Built on cloakbrowser + Playwright

Browser automation uses [cloakbrowser](https://cloakbrowser.dev/) — a stealth-patched Chromium with source-level C++ fingerprint patches — driven via Playwright. There is no CDP surface, no sidecar, no hand-rolled stealth script. One `target_id` from `interceptor_browser_launch` is everything downstream tools need.

| Capability | proxy-mcp |
|---|---|
| See/modify DOM, run JS in page | Via `interceptor_browser_snapshot` + `interceptor_browser_list_storage_keys` (also reachable from custom scripts via `page.evaluate`) |
| Read cookies, localStorage, sessionStorage | Yes — `interceptor_browser_list_cookies`, `interceptor_browser_list_storage_keys` |
| Capture HTTP request/response bodies | Via the MITM proxy (4 KB preview cap by default; `full` capture profile on persisted sessions stores complete bodies) |
| Modify requests in-flight (headers, body, mock, drop) | Yes (declarative rules, hot-reload) |
| Upstream proxy chaining (geo, auth) | Global + per-host upstreams across all clients (SOCKS4/5, HTTP, HTTPS, PAC) |
| TLS fingerprint capture (JA3/JA4/JA3S) | Yes |
| JA3 + HTTP/2 fingerprint spoofing | Proxy-side (impit re-issues matching requests with spoofed TLS 1.3, HTTP/2 frames, and header order) |
| Intercept non-browser traffic (curl, Python, Android apps) | Yes (interceptors) |
| Human-like mouse/keyboard/scroll input | `humanizer_*` tools: Bezier curves + Fitts's law for mouse, WPM + bigram + typo model for typing, eased wheel scroll — layered on top of cloakbrowser's built-in humanize mode |
| Locator-based interaction | `humanizer_click` accepts CSS/XPath selector, ARIA role + name, visible text, or form label — no pixel guessing |

**Standard flow:**

1. Call `proxy_start`
2. Optionally enable outbound fingerprint spoofing for cross-origin sub-resources: `proxy_set_fingerprint_spoof --preset chrome_136`
3. Call `interceptor_browser_launch --url "https://example.com"`
4. Drive the page: `interceptor_browser_navigate`, `interceptor_browser_snapshot`, `humanizer_click --selector "..."`, `humanizer_type --text "..."`
5. Inspect traffic: `proxy_search_traffic --query "<hostname>"`

## Tools Reference

### Lifecycle (4)

| Tool | Description |
|------|-------------|
| `proxy_start` | Start MITM proxy, auto-generate CA cert |
| `proxy_stop` | Stop proxy (traffic/cert retained) |
| `proxy_status` | Running state, port, rule/traffic counts |
| `proxy_get_ca_cert` | CA certificate PEM + SPKI fingerprint |

### Transparent / Mobile Capture (6)

| Tool | Description |
|------|-------------|
| `proxy_start_transparent` | Start second MITM listener (SNI-based, no CONNECT) on a parallel port; shares CA + rules + ring buffer with the explicit listener |
| `proxy_stop_transparent` | Stop the transparent listener |
| `proxy_transparent_status` | Running state + port + dedicated traffic count |
| `proxy_mobile_setup` | One-command mobile capture: start both listeners, inject CA into Android system store via adb (tmpfs overlay + zygote ns for Android 14+), emit a sudo-runnable iptables/sysctl/nmcli script |
| `proxy_mobile_teardown` | Reverse setup: deactivate Android target, stop transparent listener, emit teardown script |
| `proxy_mobile_detect_iface` | Probe `/sys/class/net` for a `cdc_ncm` USB interface (matches the [proxy-ap-card](https://github.com/yfe404/proxy-ap-card) firmware) |

### Upstream Proxy (4)

| Tool | Description |
|------|-------------|
| `proxy_set_upstream` | Set global upstream proxy |
| `proxy_clear_upstream` | Remove global upstream |
| `proxy_set_host_upstream` | Per-host upstream override |
| `proxy_remove_host_upstream` | Remove per-host override |

### Interception Rules (7)

| Tool | Description |
|------|-------------|
| `proxy_add_rule` | Add rule with matcher + handler |
| `proxy_update_rule` | Modify existing rule |
| `proxy_remove_rule` | Delete rule |
| `proxy_list_rules` | List all rules by priority |
| `proxy_test_rule_match` | Test which rules would match a simulated request or captured exchange, with detailed diagnostics |
| `proxy_enable_rule` | Enable a disabled rule |
| `proxy_disable_rule` | Disable without removing |

Quick debugging examples:

```bash
# Simulate a request and see which rule would win
proxy_test_rule_match --mode simulate --request '{"method":"GET","url":"https://example.com/api/v1/items","headers":{"accept":"application/json"}}'

# Evaluate a real captured exchange by ID
proxy_test_rule_match --mode exchange --exchange_id "ex_abc123"
```

### Traffic Capture (4)

| Tool | Description |
|------|-------------|
| `proxy_list_traffic` | Paginated traffic list with filters |
| `proxy_get_exchange` | Full exchange details by ID |
| `proxy_search_traffic` | Full-text search across traffic |
| `proxy_clear_traffic` | Clear capture buffer |

### Modification Shortcuts (3)

| Tool | Description |
|------|-------------|
| `proxy_inject_headers` | Add/overwrite/delete headers on matching traffic (set value to `null` to remove a header) |
| `proxy_rewrite_url` | Rewrite request URLs |
| `proxy_mock_response` | Return mock response for matched requests |

### TLS Fingerprinting (9)

| Tool | Description |
|------|-------------|
| `proxy_get_tls_fingerprints` | Get JA3/JA4 client fingerprints + JA3S for a single exchange |
| `proxy_list_tls_fingerprints` | List unique JA3/JA4 fingerprints across all traffic with counts |
| `proxy_set_ja3_spoof` | Legacy: enable JA3 spoofing (deprecated, use `proxy_set_fingerprint_spoof`) |
| `proxy_clear_ja3_spoof` | Disable fingerprint spoofing |
| `proxy_get_tls_config` | Return current TLS config (server capture, JA3 spoof state) |
| `proxy_enable_server_tls_capture` | Toggle server-side JA3S capture (monkey-patches `tls.connect`) |
| `proxy_set_fingerprint_spoof` | Enable full TLS + HTTP/2 fingerprint spoofing via impit. Supports browser presets. |
| `proxy_list_fingerprint_presets` | List available browser fingerprint presets (e.g. `chrome_131`, `chrome_136`, `chrome_136_linux`, `firefox_133`) |
| `proxy_check_fingerprint_runtime` | Check fingerprint spoofing backend readiness |

Fingerprint spoofing works by re-issuing the request from the proxy via impit (native Rust TLS/HTTP2 impersonation via rustls). TLS 1.3 and HTTP/2 fingerprints (SETTINGS, WINDOW_UPDATE, PRIORITY frames) match real browsers by construction. The origin server sees the proxy's spoofed TLS, HTTP/2, and header order — not the original client's. When a `user_agent` is set (including via presets), proxy-mcp also normalizes Chromium UA Client Hints headers (`sec-ch-ua*`) to match the spoofed User-Agent (forwarding contradictory hints is a common bot signal). **Browser exception:** when cloakbrowser is launched via `interceptor_browser_launch`, document loads and same-origin requests use the browser's native TLS (no impit), preserving fingerprint consistency for bot detection challenges. Only cross-origin sub-resource requests are re-issued with spoofed TLS. Non-browser clients (curl, spawn, HAR replay) get full TLS + UA spoofing on all requests. Use `proxy_set_fingerprint_spoof` with a browser preset for one-command setup. `proxy_set_ja3_spoof` is kept for backward compatibility but custom JA3 strings are ignored (the preset's impit browser target is used instead). JA4 fingerprints are captured (read-only) but spoofing is not supported.

### Interceptors (17)

Interceptors configure targets (browsers, processes, devices, containers) to route their traffic through the proxy automatically.

#### Discovery (3)

| Tool | Description |
|------|-------------|
| `interceptor_list` | List all interceptors with availability and active target counts |
| `interceptor_status` | Detailed status of a specific interceptor |
| `interceptor_deactivate_all` | Emergency cleanup: kill all active interceptors across all types |

#### Browser (3)

| Tool | Description |
|------|-------------|
| `interceptor_browser_launch` | Launch cloakbrowser (stealth Chromium) with proxy flags, SPKI cert trust, built-in humanize mode |
| `interceptor_browser_navigate` | Navigate the bound page via Playwright `page.goto` and verify proxy capture |
| `interceptor_browser_close` | Close a browser instance by target ID |

Stealth is source-level: cloakbrowser ships 48+ C++ patches so ja3n/ja4/akamai match real Chrome, `navigator.webdriver` is false, audio/canvas/WebGL fingerprints match real hardware. No JS stealth injection needed. First launch downloads a ~200 MB Chromium binary (cached afterwards).

#### Terminal / Process (2)

| Tool | Description |
|------|-------------|
| `interceptor_spawn` | Spawn a command with proxy env vars pre-configured (HTTP_PROXY, SSL certs, etc.) |
| `interceptor_kill` | Kill a spawned process and retrieve stdout/stderr |

Sets 18+ env vars covering curl, Node.js, Python requests, Deno, Git, npm/yarn.

#### Android ADB (4)

| Tool | Description |
|------|-------------|
| `interceptor_android_devices` | List connected Android devices via ADB |
| `interceptor_android_activate` | Full interception: inject CA cert, ADB reverse tunnel, optional Wi-Fi proxy |
| `interceptor_android_deactivate` | Remove ADB tunnel and clear Wi-Fi proxy |
| `interceptor_android_setup` | Quick setup: push CA cert + ADB reverse tunnel (no Wi-Fi proxy) |

**Caveats:** CA cert injection requires root access. Supports Android 14+ (`/apex/com.android.conscrypt/cacerts/`). Wi-Fi proxy is opt-in (default off).

#### Android Frida (3)

| Tool | Description |
|------|-------------|
| `interceptor_frida_apps` | List running apps on device via Frida |
| `interceptor_frida_attach` | Attach to app and inject SSL unpinning + proxy redirect scripts |
| `interceptor_frida_detach` | Detach Frida session from app |

**Caveats:** Requires `frida-server` running on device. Uses `frida-js` (pure JS, no native binaries on host). SSL unpinning covers OkHttp, BoringSSL, TrustManager, system TLS — but may not work against QUIC or custom TLS stacks.

#### Docker (2)

| Tool | Description |
|------|-------------|
| `interceptor_docker_attach` | Inject proxy env vars and CA cert into running container |
| `interceptor_docker_detach` | Remove proxy config from container |

Two modes: `exec` (live injection, existing processes need restart) and `restart` (stop + restart container). Uses `host.docker.internal` for proxy URL.

### Browser DevTools-equivalents (9)

Playwright-driven tools for the browser target. Each takes a `target_id` directly — no session binding, no sidecar.

| Tool | Description |
|------|-------------|
| `interceptor_browser_snapshot` | ARIA/role YAML snapshot of the page (or selector subtree) — optimized for LLM page reasoning |
| `interceptor_browser_screenshot` | Screenshot. Writes to `file_path` if provided; otherwise reports byte count only |
| `interceptor_browser_list_console` | Buffered console messages since launch, with type/text filters and pagination |
| `interceptor_browser_list_cookies` | Cookie listing with filters, pagination, truncated value previews |
| `interceptor_browser_get_cookie` | Get one cookie by `cookie_id` (value is capped to keep output bounded) |
| `interceptor_browser_list_storage_keys` | localStorage/sessionStorage key listing with value previews |
| `interceptor_browser_get_storage_value` | Get one storage value by `item_id` |
| `interceptor_browser_list_network_fields` | Header field listing from proxy-captured traffic since the browser was launched |
| `interceptor_browser_get_network_field` | Get one full header field value by `field_id` |

Network data is sourced from the MITM proxy rather than a browser-side protocol — the proxy sees every wire request regardless of what the browser reported.

### Sessions (13)

Persistent, queryable on-disk capture for long runs and post-crash analysis.

| Tool | Description |
|------|-------------|
| `proxy_session_start` | Start persistent session capture (preview or full-body mode) |
| `proxy_session_stop` | Stop and finalize the active persistent session |
| `proxy_session_status` | Runtime status for persistence (active session, bytes, disk cap errors) |
| `proxy_import_har` | Import a HAR file from disk into a new persisted session |
| `proxy_list_sessions` | List recorded sessions from disk |
| `proxy_get_session` | Get manifest/details for one session |
| `proxy_query_session` | Indexed query over recorded exchanges |
| `proxy_get_session_handshakes` | Report JA3/JA4/JA3S handshake metadata availability for session entries |
| `proxy_get_session_exchange` | Fetch one exchange from a session (with optional full bodies) |
| `proxy_replay_session` | Dry-run or execute replay of selected session requests |
| `proxy_export_har` | Export full session or filtered subset to HAR |
| `proxy_delete_session` | Delete a stored session |
| `proxy_session_recover` | Rebuild indexes from records after unclean shutdown |

`proxy_get_session_exchange` and `proxy_export_har` automatically decompress response bodies (gzip, deflate, brotli) based on the stored `content-encoding` header. The returned `responseBodyText` and `responseBodyBase64` contain the decompressed content. Raw compressed bytes are preserved on disk for exact replay fidelity.

Note on `proxy_start` with `persistence_enabled: true`: this auto-creates a session. A subsequent `proxy_session_start()` call returns the existing active session instead of failing — no need to stop and re-start.

### Humanizer — Playwright Input (5)

Human-like browser input via Playwright `page.mouse` / `page.keyboard`, layered on top of cloakbrowser's built-in humanize mode. Binds to `target_id` from `interceptor_browser_launch`.

| Tool | Description |
|------|-------------|
| `humanizer_move` | Move mouse along a Bezier curve with Fitts's law velocity scaling and eased timing |
| `humanizer_click` | Click a locator (`selector` / `role` + `name` / `text` / `label`) or raw `x,y`. Auto-waits for visible + enabled + stable + in-view before clicking |
| `humanizer_type` | Type text with per-character delays modeled on WPM, bigram frequency, shift penalty, word pauses, and optional typo injection |
| `humanizer_scroll` | Scroll with easeInOutQuad acceleration/deceleration via multiple wheel events |
| `humanizer_idle` | Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls to defeat idle detection |

All tools require `target_id` from a prior `interceptor_browser_launch`. The engine maintains tracked mouse position across calls, so `humanizer_move` followed by `humanizer_click` produces a continuous path.

**Behavioral details:**
- **Mouse paths**: Cubic Bezier curves with random control points, Fitts's law distance/size scaling, optional overshoot + correction arc
- **Typing**: Base delay from WPM, modified by bigram frequency (common pairs like "th" are faster), shift key penalty, word-boundary pauses. Optional typo injection uses QWERTY neighbor map with backspace correction
- **Scrolling**: Total delta distributed across multiple wheel events following easeInOutQuad velocity curve
- **Idle**: Periodic micro-jitter (±3px subtle / ±8px normal) and random micro-scrolls at configurable intensity

## Resources

| URI | Description |
|-----|-------------|
| `proxy://status` | Proxy running state and config |
| `proxy://ca-cert` | CA certificate PEM |
| `proxy://traffic/summary` | Traffic stats: method/status breakdown, top hostnames, TLS fingerprint stats |
| `proxy://interceptors` | All interceptor metadata and activation status |
| `proxy://sessions` | Persistent session catalog + runtime persistence status |
| `proxy://browser/primary` | Current page URL/title for the most recently launched browser instance |
| `proxy://browser/targets` | Current page state for all active browser instances |
| `proxy://sessions/{session_id}/summary` | Aggregate stats for one recorded session (resource template) |
| `proxy://sessions/{session_id}/timeline` | Time-bucketed request/error timeline (resource template) |
| `proxy://sessions/{session_id}/findings` | Top errors/slow exchanges/host error rates (resource template) |

## Usage Example

```
# Start the proxy
proxy_start

# Optional: start persistent session recording
proxy_session_start --capture_profile full --session_name "reverse-run-1"

# Configure device to use proxy (Wi-Fi settings or interceptors)
# Install CA cert on device (proxy_get_ca_cert)

# Or use interceptors to auto-configure targets:
interceptor_browser_launch                    # Launch stealth browser with proxy
interceptor_spawn --command curl --args '["https://example.com"]'  # Spawn proxied process
interceptor_android_activate --serial DEVICE_SERIAL               # Android device

# Set upstream proxy for geolocation
proxy_set_upstream --proxy_url socks5://user:pass@geo-proxy:1080

# Mock an API response
proxy_mock_response --url_pattern "/api/v1/config" --status 200 --body '{"feature": true}'

# Inject auth headers (set value to null to delete a header)
proxy_inject_headers --hostname "api.example.com" --headers '{"Authorization": "Bearer token123"}'

# View captured traffic
proxy_list_traffic --hostname_filter "api.example.com"
proxy_search_traffic --query "error"

# TLS fingerprinting
proxy_list_tls_fingerprints                # See unique JA3/JA4 fingerprints
proxy_set_ja3_spoof --ja3 "771,4865-..."   # Spoof outgoing JA3 (for non-browser clients)
proxy_set_fingerprint_spoof --preset chrome_136 --host_patterns '["example.com"]'  # Full fingerprint spoof
proxy_list_fingerprint_presets                  # Available browser presets

# Human-like browser interaction (requires interceptor_browser_launch target)
humanizer_move   --target_id "browser_<id>" --x 500 --y 300
humanizer_click  --target_id "browser_<id>" --selector "#login-button"
humanizer_click  --target_id "browser_<id>" --role "button" --name "Sign in"
humanizer_type   --target_id "browser_<id>" --text "user@example.com" --wpm 45
humanizer_scroll --target_id "browser_<id>" --delta_y 300
humanizer_idle   --target_id "browser_<id>" --duration_ms 2000 --intensity subtle

# Query/export recorded session
proxy_list_sessions
proxy_query_session --session_id SESSION_ID --hostname_contains "api.example.com"
proxy_export_har --session_id SESSION_ID
```

## Architecture

- **State**: `ProxyManager` singleton manages mockttp server, rules, traffic
- **Rule rebuild**: Rules must be set before mockttp `start()`, so rule changes trigger stop/recreate/restart cycle
- **Traffic capture**: `on('request')` + `on('response')` events, correlated by request ID
- **Ring buffer**: 1000 entries max, body previews capped at 4KB
- **TLS capture**: Client JA3/JA4 from mockttp socket metadata; server JA3S via `tls.connect` monkey-patch
- **TLS spoofing**: impit (native Rust TLS/HTTP2 impersonation via rustls); in-process, no container needed
- **Interceptors**: Managed by `InterceptorManager`, each type registers independently
- **Browser**: cloakbrowser (stealth Chromium, ~200 MB binary auto-downloaded on first launch) driven via Playwright `BrowserContext` / `Page`
- **Humanizer**: Singleton engine using Playwright's `page.mouse` / `page.keyboard`. Custom timing layer (Bezier paths, Fitts's law, bigram typing) feeds Playwright — sits on top of cloakbrowser's built-in `humanize: true`

## Testing

```bash
npm test              # All tests (unit + integration)
npm run test:unit     # Unit tests only
npm run test:integration  # Integration tests
npm run test:e2e      # E2E fingerprint tests (requires cloakbrowser + internet)
```

## Credits

### Core Libraries

| Project | Role |
|---------|------|
| [mockttp](https://github.com/httptoolkit/mockttp) | MITM proxy engine, rule system, CA generation |
| [impit](https://github.com/yfe404/impit) | Native TLS/HTTP2 fingerprint impersonation (Rust via NAPI-RS) |
| [frida-js](https://github.com/AeonLucid/frida-js) | Pure-JS Frida client for Android instrumentation |
| [cloakbrowser](https://cloakbrowser.dev/) | Stealth-patched Chromium with source-level C++ fingerprint patches |
| [playwright-core](https://playwright.dev/) | Browser automation API driving cloakbrowser |
| [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) | MCP server framework |

### Vendored Frida Scripts

All scripts in `src/frida-scripts/vendor/` are derived from **[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)** (MIT):

- `config-template.js` — proxy/cert config injection
- `android-certificate-unpinning.js` — TrustManager + OkHttp + BoringSSL hooks
- `android-system-certificate-injection.js` — runtime cert injection via KeyStore
- `android-proxy-override.js` — ProxySelector monkey-patch
- `native-tls-hook.js` — BoringSSL/OpenSSL native hooks
- `native-connect-hook.js` — libc `connect()` redirect
