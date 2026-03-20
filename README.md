# proxy-mcp

proxy-mcp is an MCP server that runs an explicit HTTP/HTTPS MITM proxy (L7). It captures requests/responses, lets you modify traffic in-flight (headers/bodies/mock/forward/drop), supports upstream proxy chaining, and records TLS fingerprints for connections to the proxy (JA3/JA4) plus optional upstream server JA3S. It also ships "interceptors" to route Chrome, CLI tools, Docker containers, and Android devices/apps through the proxy.

81 tools + 8 resources + 4 resource templates. Built on [mockttp](https://github.com/httptoolkit/mockttp).

### Boundaries

- Only sees traffic **configured to route through it** (not a network tap or packet sniffer)
- Spoofs **outgoing JA3 + HTTP/2 fingerprint + header order** (via impit — native Rust TLS impersonation), not JA4 (JA4 is capture-only)
- Can add, overwrite, or delete HTTP headers; outgoing header **order** can be controlled via fingerprint spoofing
- Returns its own CA certificate — does **not** expose upstream server certificate chains

### Pairs well with CDP/Playwright

Use CDP/Playwright for browser internals (DOM, JS execution, localStorage, cookie jar), and proxy-mcp for wire-level capture/manipulation + replay. They complement each other:

| Capability | CDP / Playwright | proxy-mcp |
|---|---|---|
| See/modify DOM, run JS in page | Yes | No |
| Read cookies, localStorage, sessionStorage | Yes (browser internals) | Yes for proxy-launched Chrome via DevTools Bridge list/get tools; for any client, sees Cookie/Set-Cookie headers on the wire |
| Capture HTTP request/response bodies | Yes for browser requests (protocol/size/streaming caveats) | Body previews only (4 KB cap, 1000-entry ring buffer) |
| Modify requests in-flight (headers, body, mock, drop) | Via route/intercept handlers | Yes (declarative rules, hot-reload) |
| Upstream proxy chaining (geo, auth) | Single browser via `--proxy-server` | Global + per-host upstreams across all clients (SOCKS4/5, HTTP, HTTPS, PAC) |
| TLS fingerprint capture (JA3/JA4/JA3S) | No | Yes |
| JA3 + HTTP/2 fingerprint spoofing | No | Proxy-side only (impit re-issues matching requests with spoofed TLS 1.3, HTTP/2 frames, and header order; does not alter the client's TLS handshake) |
| Intercept non-browser traffic (curl, Python, Android apps) | No | Yes (interceptors) |
| Human-like mouse/keyboard/scroll input | Via Playwright `page.mouse`/`page.keyboard` (instant, detectable timing) | Yes — CDP humanizer with Bezier curves, Fitts's law, WPM typing, eased scrolling |

A typical combo: launch Chrome via `interceptor_chrome_launch` (routes through proxy automatically), drive pages with Playwright/CDP, and use proxy-mcp to capture the wire traffic, inject headers, or spoof JA3 — all in the same session. For behavioral realism, use `humanizer_*` tools instead of Playwright's instant `page.click()`/`page.type()` — they dispatch human-like CDP `Input.*` events with natural timing curves.

**Attach Playwright to proxy-launched Chrome:**

1. Call `proxy_start`
2. Call `interceptor_chrome_launch`
3. Read `proxy://chrome/primary` (or call `interceptor_chrome_cdp_info`) to get `cdp.httpUrl` (Playwright) and `cdp.browserWebSocketDebuggerUrl` (raw CDP clients)
4. In Playwright:
   ```ts
   import { chromium } from "playwright";
   const browser = await chromium.connectOverCDP("http://127.0.0.1:<cdp-port>");
   ```

**Proxy-safe built-in CDP flow (single-instance safe):**

1. Call `proxy_start`
2. Call `interceptor_chrome_launch`
3. Call `interceptor_chrome_devtools_attach` with that `target_id`
4. Call `interceptor_chrome_devtools_navigate` with `devtools_session_id`
5. Call `proxy_search_traffic --query "<hostname>"` to confirm capture

**Human-like input flow (bypasses bot detection):**

1. Call `proxy_start`
2. Optionally enable fingerprint spoofing: `proxy_set_fingerprint_spoof --preset chrome_136`
3. Call `interceptor_chrome_launch --url "https://example.com"` (stealth mode auto-enabled when spoofing)
4. Use `humanizer_move` / `humanizer_click` / `humanizer_type` / `humanizer_scroll` with the `target_id`
5. Use `humanizer_idle` between actions to maintain natural presence

## HTTP Proxy Configuration

### 1) Start proxy and get endpoint

```bash
proxy_start
```

Use the returned `port` and endpoint `http://127.0.0.1:<port>`.

### 2) Browser setup (recommended: interceptor)

Use the Chrome interceptor so proxy flags and cert trust are configured automatically:

```bash
interceptor_chrome_launch --url "https://example.com"
```

Then bind DevTools safely to that same target:

```bash
interceptor_chrome_devtools_attach --target_id "chrome_<pid>"
interceptor_chrome_devtools_navigate --devtools_session_id "devtools_<id>" --url "https://apify.com"
```

### 3) Browser setup (manual fallback)

If launching Chrome manually, pass proxy flag yourself:

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
- Traffic from the wrong browser instance (fix: use `interceptor_chrome_devtools_attach`)
- HTTPS cert trust missing on target
- `NO_PROXY` bypassing expected hosts
- `chrome-devtools-mcp` not installed (`ENOENT`): `interceptor_chrome_devtools_attach` falls back to navigation-only mode. Install `chrome-devtools-mcp` for full snapshot/network/console/screenshot support.

Pull/install sidecar directly from MCP:

```bash
interceptor_chrome_devtools_pull_sidecar --version "0.2.2"
```

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

## Tools Reference

### Lifecycle (4)

| Tool | Description |
|------|-------------|
| `proxy_start` | Start MITM proxy, auto-generate CA cert |
| `proxy_stop` | Stop proxy (traffic/cert retained) |
| `proxy_status` | Running state, port, rule/traffic counts |
| `proxy_get_ca_cert` | CA certificate PEM + SPKI fingerprint |

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

Fingerprint spoofing works by re-issuing the request from the proxy via impit (native Rust TLS/HTTP2 impersonation via rustls). TLS 1.3 and HTTP/2 fingerprints (SETTINGS, WINDOW_UPDATE, PRIORITY frames) match real browsers by construction. The origin server sees the proxy's spoofed TLS, HTTP/2, and header order — not the original client's. When a `user_agent` is set (including via presets), proxy-mcp also normalizes Chromium UA Client Hints headers (`sec-ch-ua*`) to match the spoofed User-Agent (forwarding contradictory hints is a common bot signal). **Chrome browser exception:** when Chrome is launched via `interceptor_chrome_launch`, document loads and same-origin requests use Chrome's native TLS (no impit), preserving fingerprint consistency for bot detection challenges. Only cross-origin sub-resource requests are re-issued with spoofed TLS. Non-browser clients (curl, spawn, HAR replay) get full TLS + UA spoofing on all requests. Use `proxy_set_fingerprint_spoof` with a browser preset for one-command setup. `proxy_set_ja3_spoof` is kept for backward compatibility but custom JA3 strings are ignored (the preset's impit browser target is used instead). JA4 fingerprints are captured (read-only) but spoofing is not supported.

### Interceptors (18)

Interceptors configure targets (browsers, processes, devices, containers) to route their traffic through the proxy automatically.

#### Discovery (3)

| Tool | Description |
|------|-------------|
| `interceptor_list` | List all interceptors with availability and active target counts |
| `interceptor_status` | Detailed status of a specific interceptor |
| `interceptor_deactivate_all` | Emergency cleanup: kill all active interceptors across all types |

#### Chrome (4)

| Tool | Description |
|------|-------------|
| `interceptor_chrome_launch` | Launch Chrome/Chromium/Brave/Edge with proxy flags and SPKI cert trust |
| `interceptor_chrome_cdp_info` | Get CDP endpoints (HTTP + WebSocket) and tab targets for a launched Chrome |
| `interceptor_chrome_navigate` | Navigate a tab via the launched Chrome target's CDP page WebSocket and verify proxy capture |
| `interceptor_chrome_close` | Close a Chrome instance by target ID |

Launches with isolated temp profile, auto-cleaned on close. Supports `chrome`, `chromium`, `brave`, `edge`.

When fingerprint spoofing is active (`proxy_set_fingerprint_spoof`), Chrome launches in **stealth mode**: chrome-launcher's default flags that create detectable artifacts (e.g. `--disable-extensions` removing `chrome.runtime`) are replaced with a curated minimal set, and anti-detection patches are injected via CDP before any page scripts run. This covers `navigator.webdriver`, `chrome.runtime` presence, `Permissions.query`, and Error stack sanitization. Chrome keeps its **real User-Agent** (no UA override) so that bot detection JS (Kasada, Akamai) sees browser capabilities matching the actual Chrome version. Same-origin sub-resource requests also bypass impit to maintain TLS fingerprint consistency within each domain — only cross-origin requests are re-issued with spoofed TLS.

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

### DevTools Bridge (14)

Proxy-safe wrappers around a managed `chrome-devtools-mcp` sidecar, bound to a specific `interceptor_chrome_launch` target.

| Tool | Description |
|------|-------------|
| `interceptor_chrome_devtools_pull_sidecar` | Install/pull `chrome-devtools-mcp` so full DevTools bridge actions are available |
| `interceptor_chrome_devtools_attach` | Start a bound DevTools sidecar session for one Chrome interceptor target |
| `interceptor_chrome_devtools_navigate` | Navigate via bound DevTools session and verify matching proxy traffic |
| `interceptor_chrome_devtools_snapshot` | Get accessibility snapshot from bound DevTools session |
| `interceptor_chrome_devtools_list_network` | List network requests from bound DevTools session |
| `interceptor_chrome_devtools_list_console` | List console messages from bound DevTools session |
| `interceptor_chrome_devtools_screenshot` | Capture screenshot from bound DevTools session |
| `interceptor_chrome_devtools_list_cookies` | Token-efficient cookie listing with filters, pagination, and truncated value previews |
| `interceptor_chrome_devtools_get_cookie` | Get one cookie by `cookie_id` (value is capped to keep output bounded) |
| `interceptor_chrome_devtools_list_storage_keys` | Token-efficient localStorage/sessionStorage key listing with pagination and value previews |
| `interceptor_chrome_devtools_get_storage_value` | Get one storage value by `item_id` |
| `interceptor_chrome_devtools_list_network_fields` | Token-efficient header field listing from proxy-captured traffic since session creation |
| `interceptor_chrome_devtools_get_network_field` | Get one full header field value by `field_id` |
| `interceptor_chrome_devtools_detach` | Close one bound DevTools sidecar session |

Note: image payloads from DevTools responses are redacted from MCP output to avoid pushing large base64 blobs into context.
If `file_path` is provided for screenshot and sidecar returns the image inline, proxy-mcp writes it to disk in the wrapper.

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

### Humanizer — CDP Input (5)

Human-like browser input via Chrome DevTools Protocol. Dispatches `Input.*` events with realistic timing, Bezier mouse paths, and natural keystroke delays. Binds to `target_id` (Chrome interceptor target) — manages its own persistent CdpSession per target, independent of the DevTools Bridge sidecar.

| Tool | Description |
|------|-------------|
| `humanizer_move` | Move mouse along a Bezier curve with Fitts's law velocity scaling and eased timing |
| `humanizer_click` | Move to element (CSS selector) or coordinates, then click with human-like timing. Supports left/right/middle button and multi-click |
| `humanizer_type` | Type text with per-character delays modeled on WPM, bigram frequency, shift penalty, word pauses, and optional typo injection |
| `humanizer_scroll` | Scroll with easeInOutQuad acceleration/deceleration via multiple wheel events |
| `humanizer_idle` | Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls to defeat idle detection |

All tools require `target_id` from a prior `interceptor_chrome_launch`. The engine maintains tracked mouse position across calls, so `humanizer_move` followed by `humanizer_click` produces a continuous path.

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
| `proxy://chrome/devtools/sessions` | Active DevTools sidecar sessions bound to Chrome target IDs |
| `proxy://sessions` | Persistent session catalog + runtime persistence status |
| `proxy://chrome/primary` | CDP endpoints for the most recently launched Chrome instance |
| `proxy://chrome/targets` | CDP endpoints + tab targets for active Chrome instances |
| `proxy://chrome/{target_id}/cdp` | CDP endpoints for a specific Chrome instance (resource template) |
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
interceptor_chrome_launch                    # Launch Chrome with proxy
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
proxy_set_ja3_spoof --ja3 "771,4865-..."   # Spoof outgoing JA3
proxy_set_fingerprint_spoof --preset chrome_136 --host_patterns '["example.com"]'  # Full fingerprint spoof
interceptor_chrome_launch --url "https://example.com"       # With spoof active → stealth mode auto-enabled
proxy_list_fingerprint_presets                  # Available browser presets

# Human-like browser interaction (requires interceptor_chrome_launch target)
humanizer_move --target_id "chrome_<pid>" --x 500 --y 300
humanizer_click --target_id "chrome_<pid>" --selector "#login-button"
humanizer_type --target_id "chrome_<pid>" --text "user@example.com" --wpm 45
humanizer_scroll --target_id "chrome_<pid>" --delta_y 300
humanizer_idle --target_id "chrome_<pid>" --duration_ms 2000 --intensity subtle

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
- **Humanizer**: Singleton `HumanizerEngine` with persistent `CdpSession` per Chrome target, tracks mouse position across calls. Pure TypeScript — no external deps (Bezier paths, Fitts's law, bigram timing all computed internally)

## Testing

```bash
npm test              # All tests (unit + integration)
npm run test:unit     # Unit tests only
npm run test:integration  # Integration tests
npm run test:e2e      # E2E fingerprint tests (requires Chrome + internet)
```

## Credits

### Core Libraries

| Project | Role |
|---------|------|
| [mockttp](https://github.com/httptoolkit/mockttp) | MITM proxy engine, rule system, CA generation |
| [impit](https://github.com/yfe404/impit) | Native TLS/HTTP2 fingerprint impersonation (Rust via NAPI-RS) |
| [frida-js](https://github.com/AeonLucid/frida-js) | Pure-JS Frida client for Android instrumentation |
| [chrome-launcher](https://github.com/nicolo-ribaudo/chrome-launcher) | Chrome/Chromium process management |
| [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) | MCP server framework |

### Vendored Frida Scripts

All scripts in `src/frida-scripts/vendor/` are derived from **[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)** (MIT):

- `config-template.js` — proxy/cert config injection
- `android-certificate-unpinning.js` — TrustManager + OkHttp + BoringSSL hooks
- `android-system-certificate-injection.js` — runtime cert injection via KeyStore
- `android-proxy-override.js` — ProxySelector monkey-patch
- `native-tls-hook.js` — BoringSSL/OpenSSL native hooks
- `native-connect-hook.js` — libc `connect()` redirect
