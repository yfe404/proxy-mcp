# Changelog

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
