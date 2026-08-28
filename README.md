# proxy-mcp

proxy-mcp is an MCP server that runs an explicit HTTP/HTTPS MITM proxy (L7). It captures requests/responses, lets you modify traffic in-flight (headers/bodies/mock/forward/drop), supports upstream proxy chaining, and records TLS fingerprints for connections to the proxy (JA3/JA4) plus optional upstream server JA3S. Ships "interceptors" to route stealth browsers (cloakbrowser and Camoufox), CLI tools, Docker containers, and Android devices/apps through the proxy, plus Playwright-driven browser automation with locator-based click, typing, scroll, and ARIA snapshots.

74 tools + 8 resources + 3 resource templates. Built on [mockttp](https://github.com/httptoolkit/mockttp), [cloakbrowser](https://cloakbrowser.dev/), and [Camoufox](https://camoufox.com/).

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
- [Mobile Capture (Transparent Proxy)](#mobile-capture-transparent-proxy)
- [Boundaries](#boundaries)
  - [TLS ClientHello Passthrough](#tls-clienthello-passthrough-browser-via-interceptor)
- [Tools Reference](#tools-reference)
  - [Lifecycle](#lifecycle-4)
  - [Upstream Proxy](#upstream-proxy-4)
  - [Interception Rules](#interception-rules-7)
  - [Traffic Capture](#traffic-capture-4)
  - [Modification Shortcuts](#modification-shortcuts-3)
  - [TLS Fingerprinting](#tls-fingerprinting-9)
  - [Interceptors](#interceptors-21)
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
`url` or `none`. `proxy_mobile_setup` spells it `password_source`, matching the
snake_case of the rest of that tool's response. `none` means no password was applied to a URL that names a
user: either the credential is genuinely username-only, or the server does not
have both variables set for this host. The field is omitted for a URL with no
username, where the question does not arise.

Applies to `proxy_set_upstream`, `proxy_set_host_upstream` and
`proxy_mobile_setup`. A URL that already carries a password is used as-is, so
existing calls are unaffected. One credential covers all upstreams at the
pinned host; a URL without a username is left alone.

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

As with `proxy_set_upstream`, omit the password and set
`PROXY_MCP_UPSTREAM_PASSWORD` and `PROXY_MCP_UPSTREAM_HOST` in the server's
environment to keep it out of the call.

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

### Built on stealth browsers + Playwright

Browser automation uses [cloakbrowser](https://cloakbrowser.dev/) for stealth-patched Chromium and [Camoufox](https://camoufox.com/) for anti-detect Firefox, both driven through Playwright. There is no CDP sidecar or hand-rolled stealth script in proxy-mcp. Downstream tools take a `browser_*` target from `interceptor_browser_launch` or a `camoufox_*` target from `interceptor_camoufox_launch`.

| Capability | proxy-mcp |
|---|---|
| See/modify DOM, run JS in page | `interceptor_browser_evaluate` (run JS file, return value), `interceptor_browser_inject_init_script` (pre-document hook, every navigation), `interceptor_browser_add_script_tag` (DOM-visible — avoid for stealth); plus `interceptor_browser_snapshot` for ARIA reads |
| Read cookies, localStorage, sessionStorage | Yes — `interceptor_browser_list_cookies`, `interceptor_browser_list_storage_keys` |
| Capture HTTP request/response bodies | Via the MITM proxy (4 KB preview cap by default; `full` capture profile on persisted sessions stores complete bodies) |
| Modify requests in-flight (headers, body, mock, drop) | Yes (declarative rules, hot-reload) |
| Upstream proxy chaining (geo, auth) | Global + per-host upstreams across all clients (SOCKS4/5, HTTP, HTTPS, PAC) |
| TLS fingerprint capture (JA3/JA4/JA3S) | Yes |
| JA3 + HTTP/2 fingerprint spoofing | Proxy-side (impit re-issues matching requests with spoofed TLS 1.3, HTTP/2 frames, and header order) |
| Intercept non-browser traffic (curl, Python, Android apps) | Yes (interceptors) |
| Human-like mouse/keyboard/scroll input | `humanizer_*` tools call Playwright mouse/keyboard primitives on `browser_*` and `camoufox_*` targets. Cloakbrowser's own humanize patches apply when enabled at launch; Camoufox cursor humanization follows its launch config. |
| Locator-based interaction | `humanizer_click` accepts CSS/XPath selector, ARIA role + name, visible text, or form label — no pixel guessing |

**Standard flow:**

1. Call `proxy_start`
2. Optionally enable outbound fingerprint spoofing for cross-origin sub-resources: `proxy_set_fingerprint_spoof --preset chrome_136`
3. Call `interceptor_browser_launch --url "https://example.com"` or `interceptor_camoufox_launch`
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

### Interceptors (21)

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

#### Camoufox (4) — anti-detect Firefox

| Tool | Description |
|------|-------------|
| `interceptor_camoufox_launch` | Spawn camoufox as a Playwright WebSocket server, proxy + NSS CA pre-wired. Returns `wsUrl` |
| `interceptor_camoufox_info` | Get the wsUrl + ready-to-paste TS / Python `firefox.connect()` snippets |
| `interceptor_camoufox_list` | List active camoufox instances and their fingerprint details |
| `interceptor_camoufox_close` | Stop the launcher, remove the temp launcher dir + NSS profile |

Camoufox is a patched Firefox with source-level fingerprint controls (OS, WebGL vendor/renderer, fonts, locale, geoip-derived timezone, WebRTC blocking, humanize cursor). Camoufox runs as an external Python process and exposes a Playwright WS endpoint, but proxy-mcp also binds the returned `camoufox_*` target to the same `interceptor_browser_*` and `humanizer_*` tools used by cloakbrowser. Use the exposed `wsUrl` only when you need custom Playwright code outside MCP.

By default, proxy-mcp sets Camoufox fingerprint generation to the host OS (`linux`, `macos`, or `windows`) instead of Camoufox's upstream random OS list. Override with `os` when you intentionally need a different family, or pass an array such as `["windows", "macos"]` to let Camoufox choose from that subset. Launch/list/info responses include a safe `fingerprint` summary with the resolved OS, User-Agent, platform, OSCPU, screen/window dimensions, WebGL vendor/renderer, and font/voice counts; raw Camoufox config and process environment are not exposed.

**Host requirements:**

```bash
pip install "cloverlabs-camoufox[geoip]"   # active fork; daijro/camoufox stale on Firefox 135 → DataDome distrusts
python3 -m camoufox fetch official/150.0.2-alpha.26   # Firefox 150; default `fetch` still picks v135 due to repos.yml constraint

# For TLS MITM trust (NSS profile is created per-launch and the proxy CA is imported):
sudo apt install libnss3-tools     # Debian/Ubuntu
sudo dnf install nss-tools         # Fedora/RHEL
# macOS: brew install nss   (or use /Applications/Firefox.app/Contents/MacOS/certutil)
```

If `certutil` is missing, the launch still succeeds but the proxy CA is not trusted — HTTPS pages will show certificate errors. Proxy traffic is still captured.

**Usage:**

```text
proxy_start                                     // start the MITM proxy
interceptor_camoufox_launch { headless: true }  // returns { targetId, wsUrl, fingerprint, ... }
interceptor_browser_navigate --target_id "camoufox_<id>" --url "https://example.com"
interceptor_browser_snapshot --target_id "camoufox_<id>" --mode ai
interceptor_browser_list_console --target_id "camoufox_<id>"
interceptor_browser_list_cookies --target_id "camoufox_<id>"
// Or in your own Node code:
//   import { firefox } from 'playwright-core';
//   const browser = await firefox.connect(wsUrl);
//   const page = await (await browser.newContext()).newPage();
//   await page.goto('https://example.com');
interceptor_camoufox_close { target_id }        // when done
```

`playwright-core` is already a proxy-mcp dependency — Camoufox uses its `firefox` namespace via WebSocket; no extra Node packages needed. Traffic capture, TLS fingerprinting, rules, mocks, sessions, upstream chaining, and JA3/JA4 spoofing all apply to camoufox automatically because the proxy sits in front of it.

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

### Browser DevTools-equivalents (12)

Playwright-driven tools for the browser target. Each takes a `target_id` directly — no session binding, no sidecar. Works on both cloakbrowser (`browser_*` IDs) and camoufox (`camoufox_*` IDs) targets via the shared `getPageForTarget()` resolver.

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
| `interceptor_browser_evaluate` | Run a JS file in the page (file body wrapped as `(__args) => { ... }`); returns the result. `world: "isolated"` is the default. `world: "main"` is camoufox-only and requires `main_world_eval: true` at launch. On current camoufox build (cloverlabs/FF150) both permitted modes run in the page main world — mutations are page-visible |
| `interceptor_browser_inject_init_script` | Inject a JS file as `page.addInitScript` — runs before every page script on the next navigation. Cloakbrowser: isolated utility world. Camoufox (cloverlabs/FF150): page main world directly — patches reach the page but are observable by page scripts (`Function.prototype.toString` leak applies) |
| `interceptor_browser_add_script_tag` | Append a `<script>` to the current page. **DOM-visible — avoid for stealth.** Use for benign payloads where main-world execution + page visibility is intentional |

Network data is sourced from the MITM proxy rather than a browser-side protocol — the proxy sees every wire request regardless of what the browser reported.

**Stealth tradeoffs for JS injection:**

| Method | Cloakbrowser | Camoufox (cloverlabs/FF150) |
|---|---|---|
| `evaluate` isolated | Safe (isolated utility world) — rate-limit before reCAPTCHA, each call is CDP traffic | Runs in page main world; reads are invisible, mutations are page-observable |
| `evaluate` main | Not supported by Playwright API | Requires `main_world_eval: true` at launch; same realm as `isolated` on this build once enabled (`mw:` prefix does not create a distinct realm) |
| `inject_init_script` | **Best for stealth** — pre-document, no DOM artifact | Patches reach the page (good) but are observable via `Function.prototype.toString` and `window` enumeration; not stealth-safe for high-tier WAFs |
| `add_script_tag` | Detectable (DOM node, MutationObserver, CSP) | Detectable (same) |

References: [Playwright evaluate](https://playwright.dev/docs/evaluating), [Playwright addInitScript](https://playwright.dev/docs/api/class-page#page-add-init-script), [Camoufox stealth](https://camoufox.com/stealth/).

#### Worlds and isolation — what your JS can and can't see

The two backends ship different world models. Picking the wrong tool is the most common stealth footgun, so the boundary matters.

**Cloakbrowser (Chromium).** Playwright's `evaluate` runs in an isolated "utility" world that *shares globals with the page's main world*. An `addInitScript` patch to `navigator.webdriver` is visible to (a) your subsequent `evaluate` probes AND (b) anti-bot code the site loads. This is the model most "stealth playbooks" assume. Detection vectors are CDP-side (`Runtime.evaluate` chatter) — cloakbrowser's C++ patches mitigate those.

**Camoufox (cloverlabs ≥0.6 + Firefox 150 — current build).** No separate JS world. `page.evaluate` and `page.addInitScript` both run in the page's main world, the same realm as a real `<script>` tag. Implications:

- `inject_init_script` patches reach the page (e.g. `Object.defineProperty(navigator, 'webdriver', ...)` does affect what site scripts see). The DOWNSIDE: the patch is observable to anti-bot code on the page — `Function.prototype.toString.toString()` reveals replaced functions, `Object.defineProperty` hooks see the call.
- `interceptor_browser_evaluate` reads are invisible (no `window` writes, no prototype changes). Mutating evals (`() => { window.x = 1 }`) are observable.
- `world: "isolated"` and `world: "main"` accept the same script args for API compatibility but run in the same realm once `main` is enabled. `main_world_eval: true` still gates explicit `world: "main"` calls in proxy-mcp; on this build it does not create a separate execution realm.

Verify behavior on your installed build:

```bash
npx tsx scripts/camoufox-world-probe.ts --venv=/path/to/camoufox-venv
```

**Historical note.** Earlier daijro/camoufox (Firefox 135 line) ran `evaluate` and `addInitScript` in a separate Juggler scope that was invisible to the page — patches there did NOT reach site scripts ([camoufox#48](https://github.com/daijro/camoufox/issues/48)), but automation JS was equally invisible to anti-bot code. Cloverlabs/FF150 dropped that isolation. If your workflow depends on Juggler-scope invisibility, stay on daijro/FF135.

**Practical rules:**

| Use case | Cloakbrowser | Camoufox (cloverlabs/FF150) |
|---|---|---|
| Read DOM / extract data | `interceptor_browser_evaluate` (isolated) | `interceptor_browser_evaluate` — reads don't leak |
| Modify page state, click via JS | `interceptor_browser_evaluate` (isolated; globals are shared) | `interceptor_browser_evaluate` — mutations are page-visible; use sparingly on stealth-sensitive targets |
| Spoof navigator / window fingerprints | `interceptor_browser_inject_init_script` | **Configure at launch (`os`, `fonts`, `webgl_config`, `humanize`, `firefox_user_prefs`).** Source-level patches are invisible. `inject_init_script` works but its patches are observable. |
| Load a 3rd-party JS lib into the page | `interceptor_browser_add_script_tag` (page sees it — usually OK if intentional) | Same — runs in main world; DOM node is detectable |

**Stealth note**: on the current camoufox build, every JS-level mutation from automation is observable by anti-bot code on the page. Prefer source-level configuration over runtime patching. Use `evaluate` for reads, not writes, when stealth matters.

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

Human-like browser input via Playwright `page.mouse` / `page.keyboard`. Works with `browser_*` targets from `interceptor_browser_launch` and `camoufox_*` targets from `interceptor_camoufox_launch`. Cloakbrowser's own humanize patches apply when enabled at launch; Camoufox cursor humanization follows the Camoufox launch config.

| Tool | Description |
|------|-------------|
| `humanizer_move` | Move the mouse to `x,y` through the backend Playwright page |
| `humanizer_click` | Click a locator (`selector` / `role` + `name` / `text` / `label`) or raw `x,y`. Auto-waits for visible + enabled + stable + in-view before clicking |
| `humanizer_type` | Type text into the focused element via `page.keyboard.type`; optional `delay_ms` passes through to Playwright |
| `humanizer_scroll` | Dispatch one Playwright `page.mouse.wheel` event |
| `humanizer_idle` | Simulate idle behavior with mouse micro-jitter and occasional micro-scrolls to defeat idle detection |

All tools require `target_id` from a prior `interceptor_browser_launch` or `interceptor_camoufox_launch`. The engine maintains tracked mouse position across calls for coordinate-based move/click/idle behavior.

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
| `proxy://camoufox/targets` | Active camoufox instances with their wsUrl and fingerprint details |
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

# Human-like browser interaction (browser_* or camoufox_* target)
humanizer_move   --target_id "browser_<id>" --x 500 --y 300
humanizer_click  --target_id "browser_<id>" --selector "#login-button"
humanizer_click  --target_id "browser_<id>" --role "button" --name "Sign in"
humanizer_type   --target_id "browser_<id>" --text "user@example.com" --delay_ms 45
humanizer_scroll --target_id "browser_<id>" --delta_y 300
humanizer_idle   --target_id "browser_<id>" --duration_ms 2000 --intensity subtle

# Run / inject JS in the page (cloakbrowser + camoufox)
interceptor_browser_evaluate           --target_id "browser_<id>" --script_path /tmp/probe.js
interceptor_browser_evaluate           --target_id "camoufox_<id>" --script_path /tmp/probe.js --world main   # camoufox + main_world_eval=true
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
- **Browser**: cloakbrowser (stealth Chromium, ~200 MB binary auto-downloaded on first launch) and Camoufox (anti-detect Firefox, installed separately) driven via Playwright `BrowserContext` / `Page`
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
| [frida-js](https://github.com/AeonLucid/frida-js) | Pure-JS Frida client for Android instrumentation |
| [cloakbrowser](https://cloakbrowser.dev/) | Stealth-patched Chromium with source-level C++ fingerprint patches |
| [Camoufox](https://camoufox.com/) | Anti-detect Firefox backend with source-level fingerprint controls |
| [playwright-core](https://playwright.dev/) | Browser automation API driving cloakbrowser and Camoufox |
| [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk) | MCP server framework |

### Vendored Frida Scripts

All scripts in `src/frida-scripts/vendor/` are derived from **[httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)** (MIT):

- `config-template.js` — proxy/cert config injection
- `android-certificate-unpinning.js` — TrustManager + OkHttp + BoringSSL hooks
- `android-system-certificate-injection.js` — runtime cert injection via KeyStore
- `android-proxy-override.js` — ProxySelector monkey-patch
- `native-tls-hook.js` — BoringSSL/OpenSSL native hooks
- `native-connect-hook.js` — libc `connect()` redirect
