# Changelog

## 1.3.0

### New Features

- **Transparent proxy mode**: New `proxy_start_transparent`, `proxy_stop_transparent`, and `proxy_transparent_status` tools. The transparent listener receives iptables-redirected traffic (no CONNECT tunnels), shares the same CA cert, interception rules, and ring buffer as the explicit proxy. Rules are kept in sync across both listeners via the rebuild cycle.
- **Traffic source tagging**: Each captured exchange is tagged with `source: "explicit"` or `source: "transparent"` to distinguish proxy-configured traffic from iptables-redirected traffic. `proxy_list_traffic` gains a `source_filter` parameter.

### Bug Fixes

- **Android cert injection wipes system CA store** (fixes #11): `interceptor_android_activate` now saves existing system certs before mounting tmpfs, unstacks previous overlay mounts, and on Android 14+ injects the cert into the zygote mount namespace so all app processes see it.

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
