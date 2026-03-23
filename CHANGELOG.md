# Changelog

## 1.0.2

### Bug Fixes

- **Session body decompression**: `proxy_get_session_exchange(include_body: true)` and `proxy_export_har` now automatically decompress gzip/deflate/brotli response bodies using the stored `content-encoding` header. Previously returned raw compressed bytes. Raw bytes preserved on disk for replay fidelity.
- **proxy_start + proxy_session_start conflict**: `proxy_session_start()` no longer throws when a session was already auto-started by `proxy_start(persistence_enabled: true)`. Returns the existing active session with a descriptive note instead.

### Documentation

- **TLS ClientHello passthrough**: Documented that Chrome launched via `interceptor_chrome_launch` forwards its original TLS ClientHello to upstream servers (authentic browser fingerprint, not the proxy's). Added verification steps and comparison table.
- **README restructure**: Added table of contents, moved Setup/Install to the top, added session decompression and start-conflict notes to Sessions section.

## 1.0.1

- Initial public release on npm.
