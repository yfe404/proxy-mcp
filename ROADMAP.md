# proxy-mcp Roadmap

Last updated: 2026-02-11  
Current shipped baseline: commit `ec28255`

## Current Baseline (Already Shipped)

These are implemented and in the repo now:

- Optional persistent session capture (`preview` and `full` body modes)
- Session querying over indexed persisted traffic
- HAR export from full session or filtered subset
- Session recovery flow for truncated/unclean writes
- Session MCP tools:
  - `proxy_session_start`
  - `proxy_session_stop`
  - `proxy_session_status`
  - `proxy_list_sessions`
  - `proxy_get_session`
  - `proxy_query_session`
  - `proxy_get_session_exchange`
  - `proxy_export_har`
  - `proxy_delete_session`
  - `proxy_session_recover`
- Session resources/templates:
  - `proxy://sessions`
  - `proxy://sessions/{session_id}/summary`
  - `proxy://sessions/{session_id}/timeline`
  - `proxy://sessions/{session_id}/findings`
- CDP discovery resources:
  - `proxy://chrome/primary`
  - `proxy://chrome/{target_id}/cdp`
  - `proxy://chrome/targets`

## Roadmap Principles

- Scraping and reverse-engineering utility first
- MCP-native interfaces first (tools/resources/templates)
- Query-first UX for AI agents (avoid huge payload dumping)
- Crash resilience and operability over “nice to have” UI polish
- No default privacy-redaction workflow in roadmap scope

## Phase 1 (High ROI / Next)

### 1) Replay Engine (`proxy_replay_session`)
Problem solved:
- Turn observed traffic into reusable, high-throughput extraction.

Planned interface additions:
- Tool: `proxy_replay_session`
- Tool: `proxy_replay_status`
- Resource: `proxy://replay/{replay_id}/summary`

Functional requirements:
- Replay selected session traffic by filter and/or explicit sequence list
- Variable substitution (`{timestamp}`, `{nonce}`, captured token refs)
- Concurrency control, rate limiting, retry policy
- Per-request result capture (status, latency, error class)

Edge cases/failure modes:
- Token/session expiry during replay
- Target-side throttling/429 storms
- Non-idempotent endpoints replayed by mistake

Acceptance criteria:
- Can replay at least 1,000 selected requests with bounded concurrency
- Replay report includes success/failure counts and error buckets
- Supports dry-run mode (plan only, no outbound send)

Effort: M  
Dependencies: session query engine (already shipped)

### 2) Session Diffing (`proxy_diff_sessions`)
Problem solved:
- Quickly identify what changed between “works” and “fails” captures.

Planned interface additions:
- Tool: `proxy_diff_sessions`
- Resource template: `proxy://sessions/{session_id}/diff/{other_id}`

Functional requirements:
- Compare headers, query params, status codes, body field deltas
- Volatility scoring for candidate signature/auth fields
- Endpoint-level and field-level diff summaries

Edge cases/failure modes:
- Different request ordering and different request counts
- Dynamic IDs/timestamps creating noisy diffs

Acceptance criteria:
- Produces endpoint diff summary and top changed fields
- Can suppress known dynamic fields via ignore patterns

Effort: M  
Dependencies: replay + query output schema alignment

### 3) Decoder Pipeline (`proxy_decode_exchange`)
Problem solved:
- Make encoded/compressed payloads searchable and understandable.

Planned interface additions:
- Tool: `proxy_decode_exchange`
- Tool: `proxy_list_decoders`

Functional requirements:
- Built-in decoders: gzip, br, deflate, base64-json, msgpack
- Plugin decoder interface for protobuf/custom payloads
- Store decoded preview artifacts per exchange

Edge cases/failure modes:
- Binary blobs mistaken for text
- Decoder false positives

Acceptance criteria:
- Decoded views appear in tool output for supported formats
- Decoder failures are explicit and non-fatal

Effort: M  
Dependencies: persisted exchange retrieval (already shipped)

## Phase 2 (Coverage Expansion)

### 4) WebSocket/SSE Capture
Problem solved:
- Cover real-time targets that do not expose key data via plain HTTP.

Planned interface additions:
- Tool: `proxy_list_ws_streams`
- Tool: `proxy_get_ws_frames`
- Resource template: `proxy://sessions/{session_id}/ws`

Functional requirements:
- Capture WS open/close events and frame metadata
- Capture SSE streams with event segmentation
- Index by host/path/channel and searchable payload snippets

Acceptance criteria:
- WS/SSE streams visible in session summaries
- Query by stream/channel returns frame/event timelines

Effort: L  
Dependencies: capture layer extensions in proxy engine

### 5) Flow Template Generation
Problem solved:
- Convert captured traffic into reusable execution templates.

Planned interface additions:
- Tool: `proxy_generate_flow_template`
- Resource template: `proxy://sessions/{session_id}/templates`

Functional requirements:
- Build step graph from observed call dependencies
- Mark dynamic placeholders automatically
- Export templates as JSON for replay tool consumption

Acceptance criteria:
- One-click template generated from selected request slice
- Template replays successfully with variable input map

Effort: M  
Dependencies: replay engine, session indexing

### 6) CDP Convenience Bridge
Problem solved:
- Eliminate manual CDP attach translation for agent workflows.

Planned interface additions:
- Tool: `proxy_chrome_attach_info`

Functional requirements:
- Return attach-ready payload (HTTP URL + WS URL + snippet)
- Resolve from `proxy://chrome/primary` by default

Acceptance criteria:
- Agent can attach Playwright from single tool call

Effort: S  
Dependencies: current CDP resources (already shipped)

## Phase 3 (Reliability + Scale)

### 7) Durability/Checkpoint Upgrade
Problem solved:
- Reduce recovery time and data loss risk for long sessions.

Planned interface additions:
- Tool: `proxy_session_checkpoint`
- Tool: `proxy_session_verify_integrity`

Functional requirements:
- Chunked append logs with checksums
- Explicit checkpoint markers
- Faster startup index rebuild path

Acceptance criteria:
- Recovery handles very large sessions predictably
- Integrity verification reports corruption boundaries

Effort: M  
Dependencies: current session-store internals

### 8) Distributed Replay Workers
Problem solved:
- Scale replay beyond one process.

Planned interface additions:
- Tool: `proxy_replay_enqueue`
- Tool: `proxy_replay_worker_status`

Functional requirements:
- Queue-backed replay jobs
- Multiple workers consuming common jobs
- Aggregate run metrics and failure reporting

Acceptance criteria:
- Multi-worker runs complete with deterministic job accounting

Effort: L  
Dependencies: replay engine stable

### 9) Replay Parity Verification
Problem solved:
- Ensure replayed flows still match expected semantics.

Planned interface additions:
- Tool: `proxy_replay_verify`
- Resource: `proxy://replay/{replay_id}/parity`

Functional requirements:
- Compare replay outputs to baseline by schema/key fields
- Report drift severity by endpoint

Acceptance criteria:
- Produces pass/fail and drift summaries for a replay run

Effort: M  
Dependencies: replay engine + diff logic

## Prioritized Backlog

| Priority | Feature | Phase | Effort | Dependencies | Status |
|---|---|---|---|---|---|
| P1 | Replay engine | 1 | M | Session query (shipped) | Planned |
| P2 | Session diffing | 1 | M | Replay/query schema | Planned |
| P3 | Decoder pipeline | 1 | M | Persisted exchange access (shipped) | Planned |
| P4 | WebSocket/SSE capture | 2 | L | Capture layer extensions | Planned |
| P5 | Flow template generation | 2 | M | Replay + indexing | Planned |
| P6 | CDP convenience bridge | 2 | S | CDP resources (shipped) | Planned |
| P7 | Durability checkpoints | 3 | M | Session-store internals | Planned |
| P8 | Distributed replay workers | 3 | L | Replay engine stable | Planned |
| P9 | Replay parity verification | 3 | M | Replay + diff logic | Planned |

## Milestones

- M1: Replay + diff usable for one real target flow
- M2: Decoder + WS/SSE coverage for modern apps
- M3: Durability and scale features production-ready

## Testing Strategy by Phase

Phase 1:
- Replay correctness tests (ordering, retries, rate limits)
- Diff regression fixtures (known changed/unchanged captures)
- Decoder fixture corpus tests (valid/invalid payloads)

Phase 2:
- WS/SSE capture integration tests with synthetic stream server
- Template generation round-trip tests (capture -> template -> replay)
- CDP convenience attach smoke test

Phase 3:
- Crash-recovery stress tests on large sessions
- Replay queue worker concurrency and idempotency tests
- Parity verification tests against baseline fixtures

## Issue Mapping (Execution Discipline)

Create one GitHub issue per roadmap feature with:

- Problem statement
- Public MCP interface additions
- Data/storage impacts
- Edge cases and failure modes
- Acceptance criteria
- Test plan
- Dependencies/blockers

Issue naming convention:
- `[roadmap][phase-N] <feature-name>`

Example:
- `[roadmap][phase-1] replay-engine`
- `[roadmap][phase-1] session-diff`

