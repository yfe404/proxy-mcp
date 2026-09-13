# Changelog

## 3.5.3 — 2026-09-13

- **`proxy_stop` no longer closes other MCP sessions' browsers.** `proxyManager` is a process
  singleton and its `stop()` called `interceptorManager.deactivateAll()`, so in HTTP mode one
  client's `proxy_stop` tore down every other session's browsers, containers and spawned processes
  (#26). The interceptor registry now records the MCP session that activated each target, and
  `proxy_stop` deactivates only that session's targets. `proxy_stop { all: true }` keeps the old
  process-wide teardown. Targets activated over stdio, which has no session id, are unowned and
  still go down with any `proxy_stop` — stdio has one session, so nothing changes there.
- **The `McpServer` of a closed HTTP session is closed.** The transport was removed from the
  session map on close while its `McpServer` stayed alive, so a long-running HTTP server
  accumulated one server per past session (#26). Both halves are now closed and dropped together,
  and SIGINT closes every live session. The HTTP transport moved out of `src/index.ts` into
  `src/http-server.ts` so this is testable against real sessions.
- **A client-aborted request logs one debug line instead of a mockttp error.** When a browser
  navigates away or a page is torn down, mockttp's `streamToBuffer` rejects with `Error('Aborted')`
  and mockttp printed `Failed to handle request: Aborted` for every cancelled request — a dozen per
  discover walk, burying real upstream errors (#29). That one line is now dropped, and the
  cancellation is reported once as `request aborted by client: <method> <url>`, with no stack, when
  `PROXY_MCP_DEBUG` is set. Every other request failure keeps its current logging.
- **`InterceptorManager.register()` throws on a duplicate id.** It silently replaced the existing
  entry, which is how #25 orphaned live browser handles. The registry holds live handles, so the
  invariant is now structural rather than a guard at the single call site.

## 3.5.2 — 2026-09-13

- **`interceptor_browser_evaluate` honours `value_max_chars` up to 16 000 000.** The argument existed
  but was clamped to the 20 000-character default, so a caller reading a rendered DOM had to page it
  in 20 kB windows (34 round trips for a 511 kB page, measured). The default stays 20 000; the other
  devtools (cookies, storage) keep their previous caps.

## 3.5.1 — 2026-09-13

- **cloakbrowser back to 0.3.24 (exact pin).** Measured the same day 3.5.0 shipped: through the
  same Apify residential CZ route, cloakbrowser 0.3.24 (chromium 146.0.7680.177.2) passes
  alza.cz's Cloudflare managed challenge in about 12 s, while 0.5.10 (chromium 146.0.7680.177.5,
  free binary) is still on "Just a moment…" after 36 s and never resolved it across three
  countries in a full run. The other 3.5.0 changes stay. Bumping cloakbrowser again needs a
  challenge-passing check on a Cloudflare-managed site, not only example.com.

## 3.5.0 — 2026-09-13

### Removed (breaking)

The mobile capture stack, the Android/Frida device tooling and the Camoufox
backend are gone. proxy-mcp is now an explicit HTTP/HTTPS MITM proxy with three
interceptors: `terminal`, `browser` (cloakbrowser stealth Chromium) and
`docker`.

- Tools removed: `proxy_start_transparent`, `proxy_stop_transparent`,
  `proxy_transparent_status`, `proxy_mobile_setup`, `proxy_mobile_teardown`,
  `proxy_mobile_detect_iface`, `interceptor_android_devices`,
  `interceptor_android_activate`, `interceptor_android_deactivate`,
  `interceptor_android_setup`, `interceptor_frida_apps`,
  `interceptor_frida_attach`, `interceptor_frida_detach`,
  `interceptor_camoufox_launch`, `interceptor_camoufox_info`,
  `interceptor_camoufox_list`, `interceptor_camoufox_close`. 72 tools remain.
- Interceptors removed: `android-adb`, `android-frida`, `camoufox`.
  `interceptor_list` now reports exactly `terminal`, `browser`, `docker`.
- Resource removed: `proxy://camoufox/targets`.
- `interceptor_browser_evaluate` loses its `world` argument. `world: "main"`
  only ever did anything on Camoufox targets; the tool now always runs in
  Playwright's isolated utility world. Use
  `interceptor_browser_inject_init_script` for main-world patching.
- Transparent proxying is removed as a feature, not just as a tool file:
  `ProxyManager.startTransparent`/`stopTransparent`/`getTransparentStatus` and
  the second mockttp listener are gone, `proxy_status` no longer reports a
  `transparentProxy` block, and `proxy_list_traffic` loses its `source_filter`
  argument and the `source` field on each entry (every exchange came from the
  explicit listener once the transparent one was gone).
- The `frida-js` dependency and `src/frida-scripts/` are gone, so `npm run
  build` is plain `tsc` again with nothing to copy into `dist/`.

### Changed

- **cloakbrowser 0.3.24 → 0.5.10.** Every `launchContext` option this repo
  passes (`headless`, `proxy`, `args`, `humanize`, `humanPreset`, `timezone`,
  `locale`, `viewport`) keeps its name and shape, so no call-site change was
  needed. One upstream behaviour change reaches `interceptor_browser_launch`:
  since 0.4.0 a headed launch with no explicit viewport gets `viewport: null`
  (the page tracks the real window) instead of a forced 1920x947, and since
  0.4.6 the same applies headless on browser builds newer than 148. Nothing in
  proxy-mcp reads `page.viewportSize()`, and passing `viewport_width` +
  `viewport_height` still pins a fixed viewport. cloakbrowser 0.4.0 also
  dropped its `patchright` backend, which proxy-mcp never used.

### Known behaviour

- **An IPv6-only host is unreachable from a container with no IPv6 route, and
  no proxy-side setting changes that.** Measured on the Apify platform
  (`node:22-bookworm-slim`) while driving a cloakbrowser page at
  `https://www.alza.cz/` through the proxy: mockttp's passthrough failed a
  handful of upstream connections per page with
  `connect ENETUNREACH 2606:4700::…:443`, and
  `NODE_OPTIONS=--dns-result-order=ipv4first` changed nothing.

  Every one of those errors came from `brunhild.challenges.cloudflare.com`, a
  Cloudflare challenge asset that publishes AAAA records and **no A record**.
  Node was not mis-ordering a dual-stack answer — there was no IPv4 address to
  choose, which is why result order was irrelevant. Forcing the upstream
  resolver to A records only was prototyped and measured: it takes the
  `ENETUNREACH` count from 6 to 0, but only by turning the same failed request
  into a `getaddrinfo ENOTFOUND`. It does not make the asset load, so it was
  not shipped. Requests to dual-stack hosts were never affected — they already
  fall back to IPv4 through Happy Eyeballs.

  If you need those assets, give the container an IPv6 route or an upstream
  proxy that has one.

## 3.4.1 — 2026-09-13

- **Browser targets survive across MCP sessions** (#25). The HTTP transport
  builds a fresh `McpServer` per session, and each one called
  `initInterceptors()`, which re-`register`ed every interceptor on the process
  singleton `interceptorManager`. The second session therefore replaced the
  `BrowserInterceptor` with an empty instance and the browsers launched by the
  first session became unreachable (`Browser target '…' not found`) while their
  Chromium processes stayed alive. `initInterceptors()` is now idempotent: it
  registers once per process. Tool registration stays per session.

## 3.4.0 — 2026-08-28

- **Distribution moved from npmjs to GitHub.** Install/update via
  `npx -y "github:yfe404/proxy-mcp#semver:^3"` (resolves against version tags).
  Versions ≤ 3.3.2 remain on npm but receive no further updates. A `prepare`
  script builds `dist/` on install, so git installs work out of the box.

- **Upstream proxy credentials stay out of transcripts** (#22, #23, PR #24 by
  @MatousMarik):
  - `proxy_set_upstream`, `proxy_set_host_upstream`, `proxy_status`, and the
    `proxy://status` resource now redact upstream URLs: the password is masked,
    path segments are masked, and the query and fragment are dropped (a
    `pac+http://` token can live in any of those). The username is deliberately
    preserved — for providers like Apify Proxy it encodes proxy group, country
    and session id. An unparseable `proxy_url` is now rejected with an error
    instead of echoed back.
  - New env vars `PROXY_MCP_UPSTREAM_PASSWORD` + `PROXY_MCP_UPSTREAM_HOST`: a
    `proxy_url` with a username but no password gets the password filled in
    from the environment, but only when the URL's hostname matches the pinned
    host — so the credential never appears in a tool call and cannot be
    delivered to an arbitrary host. Responses report `passwordSource`
    (`env` | `url` | `none`; `password_source` on `proxy_mobile_setup`).
  - The password is scrubbed from the environment of processes spawned via
    `interceptor_spawn` and the Camoufox launcher (defence-in-depth).
  - Behavior notes: redacted URLs are also URL-normalized (an `http://`
    upstream gains a trailing `/`); a socks upstream is refused when the env
    password contains `:` (socks-proxy-agent would truncate it); a `:` in the
    username is refused on every scheme.

## 3.3.2 — 2026-05-17

- **Camoufox OS default + introspection:** `interceptor_camoufox_launch` now
  defaults fingerprint generation to the host OS instead of Camoufox's upstream
  random OS list, while still allowing explicit `os` overrides. Launch/list/info
  responses now include a safe fingerprint summary (resolved OS, UA, platform,
  OSCPU, screen/window, WebGL, font/voice counts) without exposing raw Camoufox
  config or process environment.

## 3.3.1 — 2026-05-17

- **Camoufox MCP parity:** `camoufox_*` targets now work with console and
  cookie listing through `interceptor_browser_list_console`,
  `interceptor_browser_list_cookies`, and `interceptor_browser_get_cookie`.
  This brings the browser-tier tooling in line with the existing shared
  navigate/snapshot/screenshot/evaluate/injection/humanizer path.

## 3.3.0 — 2026-05-16

### Camoufox dep swap: cloverlabs-camoufox 0.6.0 + Firefox 150

Host requirement change: `pip install "cloverlabs-camoufox[geoip]"` + `python3 -m camoufox fetch official/150.0.2-alpha.26` (cloverlabs's `repos.yml` still gates the Official line at `browser.min=beta.19`, so bare `fetch` would otherwise land v135).

Motivation: daijro/camoufox PyPI line was inactive for ~7 months and pinned at Firefox 135. DataDome and other Akamai/PerimeterX-class WAFs classify FF135 as outdated and serve unsolvable captcha challenges (`rt:c`) instead of the auto-solvable interstitial (`rt:i`). Cloverlabs is the active fork with `CONSTRAINTS.MIN_VERSION='alpha.1'`, drop-in `camoufox` import namespace.

### Behavior change — camoufox JS-execution world model

The camoufox dep swap to cloverlabs-camoufox 0.6.0 + Firefox 150 (chore branch `cloverlabs-camoufox-v150`) removes the Juggler-scope JS isolation that daijro/FF135 provided. Both `interceptor_browser_evaluate` (any `world`) and `interceptor_browser_inject_init_script` now run in the page's main world.

Consequences for callers:

- `inject_init_script` patches NOW reach the page (`Object.defineProperty(navigator, 'webdriver', ...)` actually affects what site scripts see) — the camoufox#48 limitation no longer applies on this build. The trade: those patches are observable by anti-bot code via `Function.prototype.toString` and `window` enumeration.
- `interceptor_browser_evaluate` mutations (writes to `window`, prototype patches) become observable to page scripts. Read-only evals stay safe.
- `world: "main"` and `world: "isolated"` accept the same script args for API compatibility but run in the same realm on cloverlabs/FF150. `main_world_eval: true` still gates explicit `world: "main"` calls; once enabled, the `mw:` prefix does not create a separate realm on this build.

Tool descriptions, README "Worlds and isolation" section, and `test/integration/browser-js-inject.test.ts` were updated to reflect the new behavior. The probe at `scripts/camoufox-world-probe.ts` re-verifies the model on any installed build.

## 3.2.0

### New Features

- **3 JS execution / injection tools, uniform across cloakbrowser + camoufox:**
  - `interceptor_browser_evaluate` — run a JS file in the page (`page.evaluate`), return the JSON-serialised result. File body is wrapped as `(__args) => { ... }` so it can `return` directly. `world: "isolated"` (default, stealthy) or `world: "main"` (camoufox-only via `mw:` prefix; requires `main_world_eval: true` at launch — detected up-front with a clear error message).
  - `interceptor_browser_inject_init_script` — inject a JS file as `page.addInitScript`, runs before every page script on next navigation. Safest stealth primitive on cloakbrowser; on camoufox runs in privileged Juggler scope and does NOT patch main world ([camoufox#48](https://github.com/daijro/camoufox/issues/48)) — the tool returns this caveat in its response.
  - `interceptor_browser_add_script_tag` — `page.addScriptTag` wrapper. Marked DOM-visible / not stealth in the tool description and return payload.
- All three accept an absolute `script_path` (no inline-source param). Per-backend stealth tradeoffs documented in the README "Browser DevTools-equivalents" section.
- `camoufox` launch result `details` now carries `main_world_eval: boolean` so downstream tools can branch on capability.

## 3.0.0

### New Features

- **Camoufox interceptor — anti-detect Firefox via Playwright WS.** New `CamoufoxInterceptor` (id `camoufox`) spawns `camoufox.server.launch_server()` as a Python subprocess, parses the emitted Websocket endpoint, and exposes it. The `wsUrl` allows custom Playwright code via `await firefox.connect(wsUrl)`. Proxy + NSS CA trust are pre-wired at launch time so `geoip: true` resolves locale/timezone from the proxy exit IP.
- Follow-up releases bind `camoufox_*` target IDs to the shared `interceptor_browser_*` and `humanizer_*` MCP tool path; direct `firefox.connect(wsUrl)` remains available for custom Playwright code.
- **4 new tools:** `interceptor_camoufox_launch`, `interceptor_camoufox_info`, `interceptor_camoufox_list`, `interceptor_camoufox_close`. Launch params expose camoufox's full fingerprint surface: `os`, `webgl_config`, `fonts`, `humanize`, `headless`, `addons`, `main_world_eval`, `enable_cache`, `disable_coop`, `block_webrtc`, `block_webgl`, `block_images`, `locale`, `geoip`, `port`, `ws_path`, `python_executable`, `trust_proxy_cert`, plus a raw `config` escape hatch.
- **New resource `proxy://camoufox/targets`.** Mirror of `proxy://browser/targets` for camoufox instances.

### Notes

- Original host requirements used the daijro/camoufox package line. Current Camoufox users should follow the cloverlabs/Firefox 150 install note in 3.3.0 above. NSS `certutil` (`libnss3-tools`/`nss-tools`/`brew install nss`) is still required for proxy CA trust.
- No new npm dependencies. `playwright-core` (already a runtime dep for cloakbrowser) provides the `firefox.connect(wsUrl)` client.
- All proxy-side capabilities — traffic capture, TLS fingerprint capture, rules, header injection, mocks, sessions, replay, upstream chaining, JA3 spoofing — apply to camoufox automatically because the proxy sits in front of it.

## 2.3.0

### New Features

- **Transparent proxy + one-command mobile capture setup.** New `transparent` and `mobile` tool groups for Wi-Fi-AP-based mobile capture (DHCP/DNS/iptables redirect to the MITM proxy). Documented in the README "Mobile Capture (Transparent Proxy)" section.

## 2.2.0

### Breaking Changes

- **Humanizer layer rewritten as thin wrapper over cloakbrowser-patched Playwright.** The custom Bezier/Fitts/WPM/bigram/typo code was duplicating (and fighting with) cloakbrowser's own `humanize: true` layer, and bypassed it by calling low-level `page.keyboard.press` — which dropped uppercase and symbol case. Engine now routes to `page.click`/`page.mouse.*`/`page.keyboard.type`, all patched by cloakbrowser with CDP-trusted Shift handling.
- **Tool params changed:**
  - `humanizer_click`: `move_duration_ms` removed; `timeout_ms` added (default 15000).
  - `humanizer_type`: `wpm` and `error_rate` removed; `delay_ms` added (optional passthrough to `keyboard.type`).
  - `humanizer_scroll`: `duration_ms` removed (single wheel event).
  - `humanizer_move`: `duration_ms` removed.
- `src/humanizer/path.ts` and `src/humanizer/timing.ts` deleted.

### Fixes

- **Uppercase and symbol typing now works.** The old `page.keyboard.press("Shift+a")` path produced lowercase output for some targets; cloakbrowser's patched `page.keyboard.type` uses CDP `Input.dispatchKeyEvent` with `isTrusted=true` and correct Shift framing.

## 2.1.0

### New Features

- **`interceptor_browser_list_cookies` `full` option**: Pass `full: true` to return full cookie values inline (capped at 20000 chars) under a `value` field, instead of the default truncated `value_preview`. Overrides `value_max_chars`. Avoids round-tripping through `interceptor_browser_get_cookie` per entry when full bodies are needed.

## 2.0.0

### Breaking Changes

- **Browser stack swap: `chrome-launcher` + CDP → `cloakbrowser` + Playwright.** Stealth-patched Chromium with source-level C++ fingerprint patches replaces the hand-rolled stealth script + `chrome-devtools-mcp` sidecar. `humanize: true` on by default.
- **Tools renamed.** All `interceptor_chrome_*` tools are now `interceptor_browser_*`. The 14 `interceptor_chrome_devtools_*` tools are collapsed onto 9 Playwright-driven equivalents:
  - `interceptor_chrome_launch` → `interceptor_browser_launch`
  - `interceptor_chrome_close` → `interceptor_browser_close`
  - `interceptor_chrome_navigate` → `interceptor_browser_navigate`
  - `interceptor_chrome_devtools_{snapshot,screenshot,list_console,list_cookies,get_cookie,list_storage_keys,get_storage_value,list_network_fields,get_network_field}` → `interceptor_browser_*`
- **Tools removed.** `interceptor_chrome_cdp_info`, `interceptor_chrome_devtools_{pull_sidecar,attach,detach,navigate,list_network}` are gone. There is no CDP surface and no session-binding step — tools take `target_id` directly. Network listing is now sourced from MITM proxy capture (always on).
- **Resources renamed.** `proxy://chrome/primary` → `proxy://browser/primary`, `proxy://chrome/targets` → `proxy://browser/targets`. `proxy://chrome/devtools/sessions` and the `proxy://chrome/{target_id}/cdp` template are removed.
- **Tool count: 77 → 71.**

### New Features

- **Locator-based `humanizer_click`.** No more guessing pixel coordinates. Accepts `selector` (CSS/XPath), `role` + `name`, `text`, or `label`. Auto-waits for visible + enabled + stable + in-view before clicking. Falls back to raw `x, y` if no locator is given.
- **ARIA snapshots.** `interceptor_browser_snapshot` returns a YAML-formatted role tree (via Playwright `locator.ariaSnapshot`), purpose-built for LLM page understanding.
- **Buffered console logging.** `interceptor_browser_list_console` reads from a per-target in-memory buffer populated by Playwright's `page.on("console", ...)` — no session binding needed.

### Dependencies

- Added: `cloakbrowser@^0.3.24`, `playwright-core@^1.59`.
- Removed: `chrome-launcher`, `chrome-devtools-mcp` (dynamic).
- Node requirement raised to `>=20` (cloakbrowser).

### Migration

- Replace `interceptor_chrome_launch` calls with `interceptor_browser_launch` (drop `browser` variant arg; cloakbrowser is the only browser).
- Replace the attach → call → detach pattern from the old sidecar flow with direct `target_id` parameters.
- CDP-specific fields in `details` (`port`, `cdpHttpUrl`, etc.) are gone; targets expose `url`, `headless`, `humanize`, etc.
- Custom stealth script injection is redundant — cloakbrowser handles it at the C++ level.

## 1.2.0

### New Features

- **OkHttp fingerprint presets**: `okhttp3`, `okhttp4`, and `okhttp5` presets now produce authentic OkHttp TLS fingerprints, HTTP/2 frames, and User-Agent headers. Requires `impit@0.13.0` which ships the upstream OkHttp fingerprint support (apify/impit#416).

### Dependencies

- Upgraded `impit` from `0.11.0` to `0.13.0`.

## 1.1.0

### New Features

- **`proxy_search_session_bodies`**: New tool for full-text search inside HTTP request/response bodies stored in persistent sessions. Decompresses and searches actual body content (gzip, deflate, brotli), returning grep-like context snippets around each match. Supports pre-filtering by hostname, URL, method, status code, and content-type. Works with both `full` and `preview` capture profiles (falls back to 4KB body previews when full bodies aren't available). Includes binary content detection, configurable context window, and scan/result limits for bounded resource usage.
- **`responseContentType` in session index**: Session index entries now include the response content-type, enabling efficient pre-filtering without loading full records from disk. Backward compatible with existing sessions.

### Improvements

- **`proxy_query_session` description**: Updated to clarify it searches metadata only and directs users to `proxy_search_session_bodies` for body content search.

## 1.0.2

### Bug Fixes

- **Session body decompression**: `proxy_get_session_exchange(include_body: true)` and `proxy_export_har` now automatically decompress gzip/deflate/brotli response bodies using the stored `content-encoding` header. Previously returned raw compressed bytes. Raw bytes preserved on disk for replay fidelity.
- **proxy_start + proxy_session_start conflict**: `proxy_session_start()` no longer throws when a session was already auto-started by `proxy_start(persistence_enabled: true)`. Returns the existing active session with a descriptive note instead.

### Documentation

- **TLS ClientHello passthrough**: Documented that Chrome launched via `interceptor_chrome_launch` forwards its original TLS ClientHello to upstream servers (authentic browser fingerprint, not the proxy's). Added verification steps and comparison table.
- **README restructure**: Added table of contents, moved Setup/Install to the top, added session decompression and start-conflict notes to Sessions section.

## 1.0.1

- Initial public release on npm.
