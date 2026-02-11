# Proxy MCP — Interactive Demo

> **Start the demo** by telling Claude Code:
> *"Read DEMO.md and run the demo"*

## Instructions for Claude

You are running an interactive demo of **proxy-mcp** for the user's team.

### Behavior

1. **First**, call `proxy_start` with `{"port": 0}` to start the proxy — it's needed
   by every demo. Show the port it started on.

2. **Then present the menu** below using `AskUserQuestion`. Let the user pick which
   demo to run. Use `multiSelect: false` and list the demos as options.

3. **Execute** the chosen demo by following its steps exactly.

4. **After each demo completes**, present the menu again (minus already-run demos)
   and ask "What's next?" — always include a "Stop & clean up" option.

5. **When the user picks cleanup** (or all demos are done), run the Cleanup sequence
   and deliver the Finale summary.

**Error handling:** If a step fails (e.g. Chrome not installed), explain what *would*
have happened and return to the menu. Never stop the demo on a failure.

**Tool prefix:** All tools are from the `proxy` MCP server — call them as
`mcp__proxy__<tool_name>`.

---

## Demo Menu

Present these options to the user:

| # | Demo | One-liner |
|---|------|-----------|
| A | **Chrome Interception** | Launch Chrome through the proxy, capture & inspect HTTPS traffic |
| B | **Mock API Responses** | Return fake JSON for any URL pattern, test with curl |
| C | **Header Injection** | Add custom headers to all requests in real-time |
| D | **Body Modification** | Find-and-replace inside response bodies in-flight |
| E | **TLS Fingerprinting** | Capture JA3/JA4 fingerprints from TLS handshakes |
| F | **Full Tour** | Run all demos A→E in sequence |
| — | **Stop & clean up** | Shut everything down |

---

## Startup (always run first)

**Say:** "Starting the MITM proxy..."

1. Call `proxy_start` with `{"port": 0}`
2. Call `proxy_status` with `{}`

**Say:** "Proxy is running on port {port} with auto-generated CA certificate.
All demos will route traffic through this proxy. Pick a demo to run."

Then present the menu.

---

## Demo A: Chrome Interception

**Say:** "Launching Chrome with proxy flags and certificate trust auto-configured —
zero manual setup."

**Steps:**

1. Call `interceptor_list` with `{}`
   — Show available interceptors

2. Call `interceptor_chrome_launch` with `{"url": "https://example.com"}`
   — Chrome launches with --proxy-server and SPKI cert trust flags

3. Call `interceptor_chrome_cdp_info` with `{"target_id": "<targetId from launch>", "include_targets": false}`
   — Show CDP endpoints for Playwright/DevTools attachment

   Optionally mention: the same info is also available as an MCP resource at `proxy://chrome/primary`
   (and per-target via the `proxy://chrome/{target_id}/cdp` resource template).

4. Wait 4 seconds (`sleep 4` via Bash) for the page to load

5. Call `proxy_list_traffic` with `{"limit": 20}`
   — Show captured HTTPS exchanges

6. Call `proxy_search_traffic` with `{"query": "example.com", "limit": 5}`
   — Search the captured traffic

7. Pick the **first exchange ID** from results, then call
   `proxy_get_exchange` with `{"exchange_id": "<that_id>"}`
   — Full request/response deep-dive

**Say:** "We captured {count} HTTPS exchanges from one page load. You get full
headers, sizes, timing, TLS fingerprints, and body previews (preview size is
capped). Chrome trusted our CA via the SPKI fingerprint flag, so no certificate
warnings."

**If Chrome is not available:** Explain that the interceptor also supports Chromium,
Brave, and Edge. Fall back to spawning curl instead:
- Call `interceptor_spawn` with `{"command": "curl", "args": ["-s", "https://example.com"]}`
- Wait 2 seconds, then call `proxy_list_traffic` with `{"limit": 10}`
- Pick an exchange and call `proxy_get_exchange`

Return to menu.

---

## Demo B: Mock API Responses

**Say:** "Let's mock an API endpoint. Any request matching our pattern will get a
fake response — no backend needed."

**Steps:**

1. Call `proxy_mock_response` with:
   ```json
   {
     "method": "GET",
     "url_pattern": "/api/test",
     "status": 200,
     "body": "{\"demo\": true, \"message\": \"This response was mocked by proxy-mcp\"}",
     "content_type": "application/json"
   }
   ```

2. Call `proxy_list_rules` with `{}`
   — Show the active mock rule

3. Call `interceptor_spawn` with:
   ```json
   {
     "command": "curl",
     "args": ["-s", "http://httpbin.org/api/test"]
   }
   ```
   — Spawn curl through the proxy to hit the mock

4. Wait 3 seconds, then call `proxy_list_traffic` with `{"limit": 5}`
   — Show that the mocked response was served (status 200, our JSON body)

**Say:** "The mock rule intercepted the request and returned our fake JSON. The
real httpbin.org server was never contacted. Rules match by method, URL pattern,
hostname, headers, or body content. Priority controls which rule wins if multiple
match."

Return to menu.

---

## Demo C: Header Injection

**Say:** "Now let's inject custom headers into every outgoing request — useful for
auth tokens, debug flags, or A/B test overrides."

**Steps:**

1. Call `proxy_inject_headers` with:
   ```json
   {
     "headers": {
       "X-Intercepted-By": "proxy-mcp-demo",
       "X-Demo-Timestamp": "2025-01-01T00:00:00Z"
     },
     "direction": "request"
   }
   ```

2. Call `proxy_list_rules` with `{}`
   — Show the header injection rule

3. Call `interceptor_spawn` with:
   ```json
   {
     "command": "curl",
     "args": ["-s", "-v", "http://httpbin.org/headers"]
   }
   ```
   — httpbin.org/headers echoes back all received headers

4. Wait 3 seconds, then call `proxy_list_traffic` with `{"limit": 3}`

5. Pick the httpbin exchange and call `proxy_get_exchange` with its ID
   — The response body from httpbin will show our injected headers

**Say:** "httpbin echoed back our injected headers. Every request flowing through
the proxy now carries X-Intercepted-By and X-Demo-Timestamp. You can scope
injection by hostname or URL pattern, and target requests, responses, or both."

Return to menu.

---

## Demo D: Body Modification

**Say:** "Let's modify response bodies in-flight. We'll set up a find-and-replace
rule that patches HTML as it flows through the proxy."

**Steps:**

1. Call `proxy_add_rule` with:
   ```json
   {
     "description": "Replace text in example.com responses",
     "matcher": {
       "hostname": "example.com"
     },
     "handler": {
       "type": "passthrough",
       "transformResponse": {
         "matchReplaceBody": [
           ["Example Domain", "INTERCEPTED Domain"],
           ["illustrative examples", "intercepted examples"]
         ]
       }
     }
   }
   ```

2. Call `proxy_list_rules` with `{}`
   — Show the body modification rule

3. Call `interceptor_spawn` with:
   ```json
   {
     "command": "curl",
     "args": ["-s", "http://example.com"]
   }
   ```

4. Wait 3 seconds, then call `proxy_list_traffic` with `{"limit": 3}`

5. Pick the example.com exchange and call `proxy_get_exchange` with its ID
   — The response body should show "INTERCEPTED Domain" instead of "Example Domain"

**Say:** "The HTML was modified in-flight — 'Example Domain' became 'INTERCEPTED
Domain'. This works on any content type: HTML, JSON, XML. Use it to patch API
responses, inject debug info, or test how your app handles unexpected data."

Return to menu.

---

## Demo E: TLS Fingerprinting

**Say:** "The proxy captures TLS fingerprints for every HTTPS connection — JA3 and
JA4 hashes that identify the client's TLS stack."

**Steps:**

1. Call `proxy_get_tls_config` with `{}`
   — Show current TLS config

2. If there's no HTTPS traffic yet, generate some:
   - Call `interceptor_spawn` with `{"command": "curl", "args": ["-s", "https://example.com"]}`
   - Wait 2 seconds

3. Call `proxy_list_tls_fingerprints` with `{"limit": 10}`
   — Show unique fingerprints with occurrence counts

4. If there are exchanges with TLS data, pick one and call
   `proxy_get_tls_fingerprints` with `{"exchange_id": "<id>"}`
   — Show JA3 hash, JA4 hash, and JA3S server fingerprint

**Say:** "Every TLS handshake is fingerprinted. Chrome, curl, Python, and mobile apps
all produce distinct JA3 hashes. Anti-bot systems use these to detect automation.
The proxy can also replay matching HTTPS requests via CycleTLS with a spoofed JA3
using the `proxy_set_ja3_spoof` tool. Note: this does not change the original
client's TLS fingerprint (it's proxy-side)."

Return to menu.

---

## Cleanup (always run at the end)

**Say:** "Cleaning up — shutting down all interceptors and stopping the proxy."

1. Call `interceptor_deactivate_all` with `{}`
   — Kill all Chrome instances and spawned processes

2. Call `proxy_clear_traffic` with `{}`
   — Wipe captured traffic

3. Call `proxy_stop` with `{}`
   — Shut down the proxy

4. Call `proxy_status` with `{}`
   — Confirm stopped

**Say:** "All clean. No orphaned processes, no lingering ports."

---

## Finale

After cleanup, deliver this summary:

**What we demonstrated:**
- HTTPS MITM proxy with auto-generated CA
- Zero-config browser interception
- Traffic capture with search & deep inspection (headers + sizes + timing + body previews)
- Mock responses for any URL pattern
- Header injection on requests/responses
- Response body modification in-flight
- TLS fingerprint capture (JA3/JA4)

**Also supported (not shown):**
- Android interception (ADB cert injection + reverse tunnel)
- Frida SSL unpinning (bypass cert pinning on any Android app)
- Docker container interception
- Upstream proxy chaining (SOCKS5/HTTP for geolocation)
- JA3 fingerprint spoofing via CycleTLS
- Request forwarding and connection dropping
- Per-host proxy routing

**Stats:** 54 tools, 7 resources, 4 resource templates, 5 interceptor types.
