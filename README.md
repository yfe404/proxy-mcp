# proxy-mcp

proxy-mcp is an MCP server that runs an explicit HTTP/HTTPS MITM proxy (L7). It captures requests/responses, lets you modify traffic in-flight (headers/bodies/mock/forward/drop), supports upstream proxy chaining, and records TLS fingerprints for connections to the proxy (JA3/JA4) plus optional upstream server JA3S. Ships "interceptors" to route the cloakbrowser stealth browser, CLI tools, and Docker containers through the proxy, plus Playwright-driven browser automation with locator-based click, typing, scroll, and ARIA snapshots.

72 tools + 7 resources + 3 resource templates. Built on [mockttp](https://github.com/httptoolkit/mockttp) and [cloakbrowser](https://cloakbrowser.dev/).

> [!IMPORTANT]
> **proxy-mcp is no longer published to npmjs.** npm's publishing system has
> become too annoying to be worth it — expiring tokens that silently break
> releases, and a mandatory passkey/2FA enrollment maze just to change a
> package setting. Distribution now happens directly from this repository:
>
> ```bash
> npx -y "github:yfe404/proxy-mcp#semver:^3"
> ```
>
> Versions ≤ 3.3.2 remain on npmjs but will never be updated —
> `npx -y proxy-mcp@latest` silently stays stale. Update your MCP config to the
> GitHub form above. See [Setup](#setup).

## Table of Contents

- [Setup](#setup)
- [HTTP Proxy Configuration](#http-proxy-configuration)
- [Boundaries](#boundaries)
  - [TLS ClientHello Passthrough](#tls-clienthello-passthrough-browser-via-interceptor)
- [Tools Reference](#tools-reference)
  - [Lifecycle](#lifecycle-4)
  - [Upstream Proxy](#upstream-proxy-4)
  - [Interception Rules](#interception-rules-7)
  - [Traffic Capture](#traffic-capture-4)
  - [Modification Shortcuts](#modification-shortcuts-3)
  - [TLS Fingerprinting](#tls-fingerprinting-9)
  - [Interceptors](#interceptors-10)
  - [Browser DevTools-equivalents](#browser-devtools-equivalents-12)
  - [Sessions](#sessions-14)
  - [Humanizer](#humanizer--playwright-input-5)
- [Resources](#resources)
- [Usage Example](#usage-example)
- [Architecture](#architecture)
- [Testing](#testing)
- [Credits](#credits)

## Setup

### Quick install (Claude Code)

```bash
claude mcp add proxy-mcp -- npx -y "github:yfe404/proxy-mcp#semver:^3"
```

This installs proxy-mcp as an MCP server using stdio transport, straight from
GitHub — no registry involved. The `#semver:^3` range resolves against this
repo's version tags, so new releases are picked up automatically.

> **Note:** the first install compiles from source (a `prepare` build), so it
> takes a few seconds longer than a registry tarball — subsequent launches use
> the npx cache. Why not npmjs anymore? See the [announcement](#proxy-mcp) at
> the top: their publishing system got too annoying.

**Scopes:**

```bash
# Per-user (available in all projects)
claude mcp add --scope user proxy-mcp -- npx -y "github:yfe404/proxy-mcp#semver:^3"

# Per-project (shared via .mcp.json, commit to repo)
claude mcp add --scope project proxy-mcp -- npx -y "github:yfe404/proxy-mcp#semver:^3"
```

To pin an exact release instead, use `github:yfe404/proxy-mcp#v3.4.0`.

### Prerequisites

- Node.js 20+

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

`PROXY_MCP_UPSTREAM_PASSWORD` and `PROXY_MCP_UPSTREAM_HOST` keep an upstream
proxy password out of the transcript — see
[Keeping the upstream password out of the transcript](#keeping-the-upstream-password-out-of-the-transcript).

`PROXY_MCP_UPSTREAM_IPV4_ONLY` (default on) resolves upstream hosts to A
records only, so the proxy never opens an upstream connection over IPv6. On a
host with no IPv6 route — an Apify Actor container, for instance — that stops
requests to dual-stack hosts from stalling on an unroutable AAAA address. It
does not make an AAAA-only host reachable: such a request fails as
`getaddrinfo ENOTFOUND` instead of `connect ENETUNREACH`. Set the variable to
`0` (or `false`/`no`/`off`) to restore mockttp's own resolver.

### Manual MCP configuration

The configured server alias controls Claude's generated tool prefix. The examples below use `proxy-mcp`, so Claude Code exposes tools as `mcp__proxy-mcp__<tool_name>`. If you rename the server key to `proxy`, use `mcp__proxy__<tool_name>` instead.

**Claude Code CLI:**

```bash
# stdio (default)
claude mcp add proxy-mcp -- npx -y "github:yfe404/proxy-mcp#semver:^3"

# From local clone
claude mcp add proxy-mcp -- node /path/to/proxy-mcp/dist/index.js

# HTTP transport for scripting
claude mcp add --transport http proxy-mcp http://127.0.0.1:3001/mcp
```

**`.mcp.json` (project-level, commit to repo):**

```json
{
  "mcpServers": {
    "proxy-mcp": {
      "command": "npx",
      "args": ["-y", "github:yfe404/proxy-mcp#semver:^3"]
    }
  }
}
```

**Streamable HTTP transport:**

```json
{
  "mcpServers": {
    "proxy-mcp": {
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

#### Keeping the upstream password out of the transcript

Tool calls and tool results are both persisted by the MCP client. To avoid
writing an upstream password there on every call, set it in the server's
environment and pass a URL with a username but no password.

Two variables are required, and both have to be in the environment of the
**server process**, which the MCP client spawns. Exporting them in the shell you
launch the client from may reach it — CLI clients pass their own environment
through — but that depends on the client and is lost the moment the server is
started any other way. Put them in the client's server config:

| variable | meaning |
|---|---|
| `PROXY_MCP_UPSTREAM_PASSWORD` | the password to fill in |
| `PROXY_MCP_UPSTREAM_HOST` | the only hostname it may be sent to — a bare hostname, no scheme, port or path |

```bash
claude mcp add proxy-mcp \
  -e PROXY_MCP_UPSTREAM_PASSWORD=s3cret \
  -e PROXY_MCP_UPSTREAM_HOST=upstream.example \
  -- npx -y "github:yfe404/proxy-mcp#semver:^3"
```

```json
{
  "mcpServers": {
    "proxy-mcp": {
      "command": "npx",
      "args": ["-y", "github:yfe404/proxy-mcp#semver:^3"],
      "env": {
        "PROXY_MCP_UPSTREAM_PASSWORD": "s3cret",
        "PROXY_MCP_UPSTREAM_HOST": "upstream.example"
      }
    }
  }
}
```

Then omit the password from the call:

```bash
proxy_set_upstream --proxy_url "http://user@upstream.example:1080"
# routes as http://user:s3cret@upstream.example:1080
```

**Why the host variable exists.** Without it, a caller who cannot read the
password could still name any host and have the password delivered there — the
proxy sends it on the first request, and the transcript would show only `***`.
The hostname is matched case-insensitively and exactly, with no wildcards; the
port is not part of the match, so one variable covers a provider offering
several. A URL naming any other host is left alone. If
`PROXY_MCP_UPSTREAM_PASSWORD` is set and `PROXY_MCP_UPSTREAM_HOST` is not,
nothing is merged at all: a half-configuration fails closed rather than
becoming an unbound credential.

> **This keeps the password out of tool arguments and responses, not out of
> reach.** `interceptor_spawn` runs an arbitrary command as the server user, so
> a caller can read the client config file the password is configured in — and
> on Linux `/proc/<pid>/environ`. The variable removes the routine exposure of
> writing a credential into every tool call; it is not a sandbox, and anyone who
> can call `interceptor_spawn` should be treated as able to obtain the password.

The response reports which credential was used — `passwordSource` is `env`,
`url` or `none`. `none` means no password was applied to a URL that names a
user: either the credential is genuinely username-only, or the server does not
have both variables set for this host. The field is omitted for a URL with no
username, where the question does not arise.

Applies to `proxy_set_upstream` and `proxy_set_host_upstream`. A URL that
already carries a password is used as-is, so existing calls are unaffected. One
credential covers all upstreams at the pinned host; a URL without a username is
left alone.

> **Username-only credentials at the pinned host cannot be expressed.** A URL
> with a username and no password is exactly the syntax that requests the
> merge, and `user:@host` cannot signal otherwise — the URL parser erases the
> empty password before the server sees it. If the pinned host authenticates on
> the username alone, unset `PROXY_MCP_UPSTREAM_PASSWORD` for that server.

> **`socks*://` upstreams: no `:` in the password.** socks-proxy-agent splits
> the credential on the first `:` and keeps only what follows, so `pa:ss` would
> authenticate as `pa`. Rather than deliver half a password silently, a socks
> upstream is **refused** with an error when `PROXY_MCP_UPSTREAM_PASSWORD`
> contains `:`. The truncation itself is a toolchain limitation, not something
> this introduces — a literal `socks5://user:pa%3Ass@host:1080` truncates the
> same way, and nothing can guard that. `http://`, `https://` and `pac+http://`
> upstreams take the whole password.

> **A `:` in the *username* is refused on every scheme.** Basic auth splits the
> decoded pair at the first colon (RFC 7617), and socks-proxy-agent does the
> same, so a username of `gro:ups` with password `s3cret` reaches the proxy as
> user `gro`, password `ups:s3cret` — the merged password silently discarded.
> No scheme can carry it, so the merge refuses rather than guess. Put the whole
> credential in `proxy_url` instead.

Responses redact credentials — the password in userinfo, with path segments
masked and the query and fragment dropped, since a `pac+http://` token may live
in any of those:

```
Global upstream set to http://user:***@upstream.example:1080/
Global upstream set to pac+http://pac.example.com/***
```

`proxy_status` and the `proxy://status` resource are redacted the same way. A
PAC URL's filename is masked along with the rest of the path, so a confirmation
message shows the host and nothing else.

**The username is not redacted.** For several providers it is configuration
rather than a secret — Apify Proxy encodes proxy group, country and
sticky-session id there — and showing it is what makes the confirmation useful.
If your provider puts a secret in the username field, do not rely on these
messages being safe to share.

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

### Built on stealth browsers + Playwright

Browser automation uses [cloakbrowser](https://cloakbrowser.dev/) for stealth-patched Chromium, driven through Playwright. There is no CDP sidecar or hand-rolled stealth script in proxy-mcp. Downstream tools take a `browser_*` target from `interceptor_browser_launch`.

| Capability | proxy-mcp |
|---|---|
| See/modify DOM, run JS in page | `interceptor_browser_evaluate` (run JS file, return value), `interceptor_browser_inject_init_script` (pre-document hook, every navigation), `interceptor_browser_add_script_tag` (DOM-visible — avoid for stealth); plus `interceptor_browser_snapshot` for ARIA reads |
| Read cookies, localStorage, sessionStorage | Yes — `interceptor_browser_list_cookies`, `interceptor_browser_list_storage_keys` |
| Capture HTTP request/response bodies | Via the MITM proxy (4 KB preview cap by default; `full` capture profile on persisted sessions stores complete bodies) |
| Modify requests in-flight (headers, body, mock, drop) | Yes (declarative rules, hot-reload) |
| Upstream proxy chaining (geo, auth) | Global + per-host upstreams across all clients (SOCKS4/5, HTTP, HTTPS, PAC) |
| TLS fingerprint capture (JA3/JA4/JA3S) | Yes |
| JA3 + HTTP/2 fingerprint spoofing | Proxy-side (impit re-issues matching requests with spoofed TLS 1.3, HTTP/2 frames, and header order) |
| Intercept non-browser traffic (curl, Python, Docker containers) | Yes (interceptors) |
| Human-like mouse/keyboard/scroll input | `humanizer_*` tools call Playwright mouse/keyboard primitives on `browser_*` targets. Cloakbrowser's own humanize patches apply when enabled at launch. |
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

### Interceptors (10)

Interceptors configure targets (browsers, processes, containers) to route their traffic through the proxy automatically.

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

#### Docker (2)

| Tool | Description |
|------|-------------|
| `interceptor_docker_attach` | Inject proxy env vars and CA cert into running container |
| `interceptor_docker_detach` | Remove proxy config from container |

Two modes: `exec` (live injection, existing processes need restart) and `restart` (stop + restart container). Uses `host.docker.internal` for proxy URL.

### Browser DevTools-equivalents (12)

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
| `interceptor_browser_evaluate` | Run a JS file in the page (file body wrapped as `(__args) => { ... }`); returns the result. Runs in the isolated utility world |
| `interceptor_browser_inject_init_script` | Inject a JS file as `page.addInitScript` — runs before every page script on the next navigation. Injected into the isolated utility world |
| `interceptor_browser_add_script_tag` | Append a `<script>` to the current page. **DOM-visible — avoid for stealth.** Use for benign payloads where main-world execution + page visibility is intentional |

Network data is sourced from the MITM proxy rather than a browser-side protocol — the proxy sees every wire request regardless of what the browser reported.

**Stealth tradeoffs for JS injection:**

| Method | Cloakbrowser |
|---|---|
| `evaluate` | Safe (isolated utility world) — rate-limit before reCAPTCHA, each call is CDP traffic |
| `inject_init_script` | **Best for stealth** — pre-document, no DOM artifact |
| `add_script_tag` | Detectable (DOM node, MutationObserver, CSP) |

References: [Playwright evaluate](https://playwright.dev/docs/evaluating), [Playwright addInitScript](https://playwright.dev/docs/api/class-page#page-add-init-script).

#### Worlds and isolation — what your JS can and can't see

Playwright's `evaluate` runs in an isolated "utility" world that *shares globals with the page's main world*. An `addInitScript` patch to `navigator.webdriver` is visible to (a) your subsequent `evaluate` probes AND (b) anti-bot code the site loads. This is the model most "stealth playbooks" assume. Detection vectors are CDP-side (`Runtime.evaluate` chatter) — cloakbrowser's C++ patches mitigate those.

**Practical rules:**

| Use case | Tool |
|---|---|
| Read DOM / extract data | `interceptor_browser_evaluate` |
| Modify page state, click via JS | `interceptor_browser_evaluate` (globals are shared with the page) |
| Spoof navigator / window fingerprints | `interceptor_browser_inject_init_script` |
| Load a 3rd-party JS lib into the page | `interceptor_browser_add_script_tag` (page sees it — usually OK if intentional) |

### Sessions (14)

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
| `proxy_search_session_bodies` | Search request/response bodies stored in a persistent session, with context snippets |
| `proxy_get_session_handshakes` | Report JA3/JA4/JA3S handshake metadata availability for session entries |
| `proxy_get_session_exchange` | Fetch one exchange from a session (with optional full bodies) |
| `proxy_replay_session` | Dry-run or execute replay of selected session requests |
| `proxy_export_har` | Export full session or filtered subset to HAR |
| `proxy_delete_session` | Delete a stored session |
| `proxy_session_recover` | Rebuild indexes from records after unclean shutdown |

`proxy_get_session_exchange` and `proxy_export_har` automatically decompress response bodies (gzip, deflate, brotli) based on the stored `content-encoding` header. The returned `responseBodyText` and `responseBodyBase64` contain the decompressed content. Raw compressed bytes are preserved on disk for exact replay fidelity.

Note on `proxy_start` with `persistence_enabled: true`: this auto-creates a session. A subsequent `proxy_session_start()` call returns the existing active session instead of failing — no need to stop and re-start.

### Humanizer — Playwright Input (5)

Human-like browser input via Playwright `page.mouse` / `page.keyboard`. Works with `browser_*` targets from `interceptor_browser_launch`. Cloakbrowser's own humanize patches apply when enabled at launch.

| Tool | Description |
|------|-------------|
| `humanizer_move` | Move the mouse to `x,y` through the backend Playwright page |
| `humanizer_click` | Click a locator (`selector` / `role` + `name` / `text` / `label`) or raw `x,y`. Auto-waits for visible + enabled + stable + in-view before clicking |
| `humanizer_type` | Type text into the focused element via `page.keyboard.type`; optional `delay_ms` passes through to Playwright |
| `humanizer_scroll` | Dispatch one Playwright `page.mouse.wheel` event |
| `humanizer_idle` | Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls to defeat idle detection |

All tools require `target_id` from a prior `interceptor_browser_launch`. The engine maintains tracked mouse position across calls for coordinate-based move/click/idle behavior.

**Behavioral details:**
- **Mouse**: `humanizer_move` calls `page.mouse.move`; locator clicks call Playwright locators and raw-coordinate clicks call `page.mouse.click`
- **Typing**: `humanizer_type` calls `page.keyboard.type(text, { delay })` when `delay_ms` is provided; no WPM, typo, or bigram model is implemented in proxy-mcp
- **Scrolling**: `humanizer_scroll` sends one wheel event with the requested delta
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

# Use interceptors to auto-configure targets:
interceptor_browser_launch                    # Launch stealth browser with proxy
interceptor_spawn --command curl --args '["https://example.com"]'  # Spawn proxied process

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

# Human-like browser interaction (browser_* target)
humanizer_move   --target_id "browser_<id>" --x 500 --y 300
humanizer_click  --target_id "browser_<id>" --selector "#login-button"
humanizer_click  --target_id "browser_<id>" --role "button" --name "Sign in"
humanizer_type   --target_id "browser_<id>" --text "user@example.com" --delay_ms 45
humanizer_scroll --target_id "browser_<id>" --delta_y 300
humanizer_idle   --target_id "browser_<id>" --duration_ms 2000 --intensity subtle

# Run / inject JS in the page
interceptor_browser_evaluate           --target_id "browser_<id>" --script_path /tmp/probe.js
interceptor_browser_inject_init_script --target_id "browser_<id>" --script_path /tmp/hook.js   # applies on next navigation
interceptor_browser_add_script_tag     --target_id "browser_<id>" --script_path /tmp/lib.js    # DOM-visible — avoid for stealth

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
- **Humanizer**: Singleton engine using Playwright's `page.mouse` / `page.keyboard`, plus local mouse-position tracking for idle jitter

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
| [cloakbrowser](https://cloakbrowser.dev/) | Stealth-patched Chromium with source-level C++ fingerprint patches |
| [playwright-core](https://playwright.dev/) | Browser automation API driving cloakbrowser |
| [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) | MCP server framework |
