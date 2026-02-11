# proxy-mcp

proxy-mcp is an MCP server that runs an explicit HTTP/HTTPS MITM proxy (L7). It captures requests/responses, lets you modify traffic in-flight (headers/bodies/mock/forward/drop), supports upstream proxy chaining, and records TLS fingerprints for connections to the proxy (JA3/JA4) plus optional upstream server JA3S. It also ships "interceptors" to route Chrome, CLI tools, Docker containers, and Android devices/apps through the proxy.

63 tools + 8 resources + 4 resource templates. Built on [mockttp](https://github.com/httptoolkit/mockttp).

### Boundaries

- Only sees traffic **configured to route through it** (not a network tap or packet sniffer)
- Spoofs **outgoing JA3 only** (via CycleTLS), not JA4 (JA4 is capture-only)
- Can add, overwrite, or delete HTTP headers — does **not** control header order
- Returns its own CA certificate — does **not** expose upstream server certificate chains

### Pairs well with CDP/Playwright

Use CDP/Playwright for browser internals (DOM, JS execution, localStorage, cookie jar), and proxy-mcp for wire-level capture/manipulation + replay. They complement each other:

| Capability | CDP / Playwright | proxy-mcp |
|---|---|---|
| See/modify DOM, run JS in page | Yes | No |
| Read cookies, localStorage, sessionStorage | Yes (browser cookie jar) | No (but sees Cookie/Set-Cookie headers on the wire) |
| Capture HTTP request/response bodies | Yes for browser requests (protocol/size/streaming caveats) | Body previews only (4 KB cap, 1000-entry ring buffer) |
| Modify requests in-flight (headers, body, mock, drop) | Via route/intercept handlers | Yes (declarative rules, hot-reload) |
| Upstream proxy chaining (geo, auth) | Single browser via `--proxy-server` | Global + per-host upstreams across all clients (SOCKS4/5, HTTP, HTTPS, PAC) |
| TLS fingerprint capture (JA3/JA4/JA3S) | No | Yes |
| JA3 spoofing | No | Proxy-side only (CycleTLS re-issues matching requests with spoofed JA3; does not alter the client's TLS handshake) |
| Intercept non-browser traffic (curl, Python, Android apps) | No | Yes (interceptors) |

A typical combo: launch Chrome via `interceptor_chrome_launch` (routes through proxy automatically), drive pages with Playwright/CDP, and use proxy-mcp to capture the wire traffic, inject headers, or spoof JA3 — all in the same session.

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

For HTTPS MITM, the proxy CA must be trusted in the target environment (`proxy_get_ca_cert`).

### 4) Process/app HTTP proxy env vars

Most CLI/SDK clients follow:

```bash
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
NO_PROXY=localhost,127.0.0.1
```

Or let proxy-mcp configure env/cert automatically:

```bash
interceptor_spawn --command curl --args '["-s","https://example.com"]'
```

### 5) Explicit HTTP client examples

```bash
curl --proxy http://127.0.0.1:<port> http://example.com
curl --proxy http://127.0.0.1:<port> https://example.com
```

### 6) Upstream HTTP proxy chaining

Set optional proxy chaining from proxy-mcp to another upstream proxy:

```bash
proxy_set_upstream --proxy_url "http://user:pass@upstream-host:8080"
```

Model:
- Client/app -> `proxy-mcp` (local explicit proxy)
- `proxy-mcp` -> upstream proxy (optional chaining layer)

### 7) Validate and troubleshoot quickly

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

## Setup

```bash
npm install
npm run build
```

### Claude Code `.mcp.json`

```json
{
  "mcpServers": {
    "proxy": {
      "command": "node",
      "args": ["/path/to/proxy-mcp/dist/index.js"]
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

### Interception Rules (6)

| Tool | Description |
|------|-------------|
| `proxy_add_rule` | Add rule with matcher + handler |
| `proxy_update_rule` | Modify existing rule |
| `proxy_remove_rule` | Delete rule |
| `proxy_list_rules` | List all rules by priority |
| `proxy_enable_rule` | Enable a disabled rule |
| `proxy_disable_rule` | Disable without removing |

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

### TLS Fingerprinting (6)

| Tool | Description |
|------|-------------|
| `proxy_get_tls_fingerprints` | Get JA3/JA4 client fingerprints + JA3S for a single exchange |
| `proxy_list_tls_fingerprints` | List unique JA3/JA4 fingerprints across all traffic with counts |
| `proxy_set_ja3_spoof` | Enable JA3 spoofing via CycleTLS for outgoing requests |
| `proxy_clear_ja3_spoof` | Disable JA3 spoofing and shut down CycleTLS |
| `proxy_get_tls_config` | Return current TLS config (server capture, JA3 spoof state) |
| `proxy_enable_server_tls_capture` | Toggle server-side JA3S capture (monkey-patches `tls.connect`) |

JA3 spoofing works by re-issuing the request from the proxy via CycleTLS with a specified JA3 string. The origin server sees the proxy's spoofed fingerprint, not the original client's. JA4 fingerprints are captured (read-only) but spoofing is not supported.

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

### DevTools Bridge (8)

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
| `interceptor_chrome_devtools_detach` | Close one bound DevTools sidecar session |

### Sessions (10)

Persistent, queryable on-disk capture for long runs and post-crash analysis.

| Tool | Description |
|------|-------------|
| `proxy_session_start` | Start persistent session capture (preview or full-body mode) |
| `proxy_session_stop` | Stop and finalize the active persistent session |
| `proxy_session_status` | Runtime status for persistence (active session, bytes, disk cap errors) |
| `proxy_list_sessions` | List recorded sessions from disk |
| `proxy_get_session` | Get manifest/details for one session |
| `proxy_query_session` | Indexed query over recorded exchanges |
| `proxy_get_session_exchange` | Fetch one exchange from a session (with optional full bodies) |
| `proxy_export_har` | Export full session or filtered subset to HAR |
| `proxy_delete_session` | Delete a stored session |
| `proxy_session_recover` | Rebuild indexes from records after unclean shutdown |

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
- **Interceptors**: Managed by `InterceptorManager`, each type registers independently

## Testing

```bash
npm test              # All tests
npm run test:unit     # Unit tests only
npm run test:integration  # Integration tests
```

## Credits

### Core Libraries

| Project | Role |
|---------|------|
| [mockttp](https://github.com/httptoolkit/mockttp) | MITM proxy engine, rule system, CA generation |
| [CycleTLS](https://github.com/Danny-Dasilva/CycleTLS) | JA3 spoofing via Go TLS subprocess |
| [frida-js](https://github.com/AeonLucid/frida-js) | Pure-JS Frida client for Android instrumentation |
| [chrome-launcher](https://github.com/nicolo-ribaudo/chrome-launcher) | Chrome/Chromium process management |
| [dockerode](https://github.com/apocas/dockerode) | Docker API client |
| [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) | MCP server framework |

### Vendored Frida Scripts

All scripts in `src/frida-scripts/vendor/` are derived from **[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)** (MIT):

- `config-template.js` — proxy/cert config injection
- `android-certificate-unpinning.js` — TrustManager + OkHttp + BoringSSL hooks
- `android-system-certificate-injection.js` — runtime cert injection via KeyStore
- `android-proxy-override.js` — ProxySelector monkey-patch
- `native-tls-hook.js` — BoringSSL/OpenSSL native hooks
- `native-connect-hook.js` — libc `connect()` redirect
