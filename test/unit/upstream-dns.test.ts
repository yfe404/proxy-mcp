import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  createIpv4OnlyLookup,
  isUpstreamIpv4OnlyEnabled,
  ensureUpstreamLookupOptions,
  type RawDnsLookup,
} from "../../src/upstream-dns.js";

/**
 * Records every call the wrapper makes to the underlying dns.lookup and
 * answers with a scripted result.
 */
function fakeLookup(
  answer: (hostname: string, options: Record<string, unknown>) => [NodeJS.ErrnoException | null, ...unknown[]],
): RawDnsLookup & { calls: Array<{ hostname: string; options: Record<string, unknown> }> } {
  const calls: Array<{ hostname: string; options: Record<string, unknown> }> = [];
  const fn = ((hostname: string, options: Record<string, unknown>, cb: (...a: unknown[]) => void) => {
    calls.push({ hostname, options });
    const [err, ...rest] = answer(hostname, options);
    setImmediate(() => cb(err, ...rest));
  }) as RawDnsLookup & { calls: typeof calls };
  fn.calls = calls;
  return fn;
}

function callLookup(
  lookup: ReturnType<typeof createIpv4OnlyLookup>,
  hostname: string,
  options?: Record<string, unknown>,
): Promise<unknown[]> {
  return new Promise((resolve) => {
    const cb = (...args: unknown[]) => resolve(args);
    if (options === undefined) (lookup as (h: string, c: unknown) => void)(hostname, cb);
    else (lookup as (h: string, o: unknown, c: unknown) => void)(hostname, options, cb);
  });
}

describe("isUpstreamIpv4OnlyEnabled", () => {
  it("defaults to true when PROXY_MCP_UPSTREAM_IPV4_ONLY is unset or empty", () => {
    assert.equal(isUpstreamIpv4OnlyEnabled({}), true);
    assert.equal(isUpstreamIpv4OnlyEnabled({ PROXY_MCP_UPSTREAM_IPV4_ONLY: "" }), true);
  });

  it("is false for the documented off values, case- and space-insensitively", () => {
    for (const raw of ["0", "false", "FALSE", "no", "off", " 0 ", "Off"]) {
      assert.equal(
        isUpstreamIpv4OnlyEnabled({ PROXY_MCP_UPSTREAM_IPV4_ONLY: raw }),
        false,
        `${JSON.stringify(raw)} should disable the flag`,
      );
    }
  });

  it("is true for anything else", () => {
    for (const raw of ["1", "true", "yes", "on"]) {
      assert.equal(isUpstreamIpv4OnlyEnabled({ PROXY_MCP_UPSTREAM_IPV4_ONLY: raw }), true, raw);
    }
  });
});

describe("createIpv4OnlyLookup", () => {
  it("forces family 4 while preserving the caller's other options", async () => {
    const raw = fakeLookup(() => [null, [{ address: "93.184.216.34", family: 4 }]]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 0 });

    await callLookup(lookup, "example.com", { family: 0, all: true, hints: 1024 });

    assert.equal(raw.calls.length, 1);
    assert.deepEqual(raw.calls[0].options, { family: 4, all: true, hints: 1024 });
  });

  it("forces family 4 when called in the two-argument (hostname, callback) form", async () => {
    const raw = fakeLookup(() => [null, "93.184.216.34", 4]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 0 });

    const result = await callLookup(lookup, "example.com");

    assert.deepEqual(raw.calls[0].options, { family: 4 });
    assert.deepEqual(result, [null, "93.184.216.34", 4]);
  });

  it("never asks for an IPv6 family even when the caller requests one", async () => {
    const raw = fakeLookup(() => [null, "93.184.216.34", 4]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 0 });

    await callLookup(lookup, "cloudflare.com", { family: 6 });

    assert.equal(raw.calls[0].options.family, 4);
  });

  it("passes the underlying result straight back to the caller", async () => {
    const addresses = [{ address: "1.2.3.4", family: 4 }, { address: "5.6.7.8", family: 4 }];
    const raw = fakeLookup(() => [null, addresses]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 0 });

    const result = await callLookup(lookup, "example.com", { all: true });

    assert.deepEqual(result, [null, addresses]);
  });

  it("propagates lookup errors", async () => {
    const err = Object.assign(new Error("getaddrinfo ENOTFOUND nope.invalid"), { code: "ENOTFOUND" });
    const raw = fakeLookup(() => [err]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 0 });

    const [received] = await callLookup(lookup, "nope.invalid", { all: false });

    assert.equal(received, err);
  });

  it("caches successful answers for the configured window", async () => {
    const raw = fakeLookup(() => [null, "1.2.3.4", 4]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 10_000 });

    const first = await callLookup(lookup, "example.com", { all: false });
    const second = await callLookup(lookup, "example.com", { all: false });

    assert.equal(raw.calls.length, 1, "second lookup should be served from cache");
    assert.deepEqual(second, first);
  });

  it("keys the cache on the request shape, so an all:true lookup is not served an all:false answer", async () => {
    const raw = fakeLookup((_h, o) => (o.all ? [null, [{ address: "1.2.3.4", family: 4 }]] : [null, "1.2.3.4", 4]));
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 10_000 });

    await callLookup(lookup, "example.com", { all: false });
    const all = await callLookup(lookup, "example.com", { all: true });

    assert.equal(raw.calls.length, 2);
    assert.deepEqual(all, [null, [{ address: "1.2.3.4", family: 4 }]]);
  });

  it("does not cache failures", async () => {
    const err = Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    const raw = fakeLookup(() => [err]);
    const lookup = createIpv4OnlyLookup({ lookup: raw, cacheMs: 10_000 });

    await callLookup(lookup, "nope.invalid", { all: false });
    await callLookup(lookup, "nope.invalid", { all: false });

    assert.equal(raw.calls.length, 2);
  });

  it("resolves a real IPv4 address through node's resolver", async () => {
    const lookup = createIpv4OnlyLookup({ cacheMs: 0 });
    const [err, address, family] = await callLookup(lookup, "localhost", { all: false });
    assert.equal(err, null, String(err));
    assert.equal(family, 4);
    assert.equal(address, "127.0.0.1");
  });
});

describe("ensureUpstreamLookupOptions", () => {
  it("returns undefined when the flag is off, leaving mockttp's default resolver in place", async () => {
    assert.equal(await ensureUpstreamLookupOptions({ PROXY_MCP_UPSTREAM_IPV4_ONLY: "0" }), undefined);
  });

  it("returns a token that mockttp resolves to the IPv4-only lookup", async () => {
    const token = await ensureUpstreamLookupOptions({ PROXY_MCP_UPSTREAM_IPV4_ONLY: "1" });
    assert.ok(token, "expected a lookupOptions token");

    const { getDnsLookupFunction } = await import("mockttp/dist/rules/passthrough-handling");
    const resolved = getDnsLookupFunction(token);

    const [err, address, family] = await new Promise<unknown[]>((resolve) => {
      (resolved as (h: string, o: unknown, c: (...a: unknown[]) => void) => void)(
        "localhost",
        { family: 6, all: false },
        (...args: unknown[]) => resolve(args),
      );
    });
    assert.equal(err, null, String(err));
    assert.equal(family, 4, "mockttp must get an IPv4 answer even when asked for family 6");
    assert.equal(address, "127.0.0.1");
  });

  it("returns the same token on repeated calls, so mockttp's memoisation stays warm", async () => {
    const a = await ensureUpstreamLookupOptions({ PROXY_MCP_UPSTREAM_IPV4_ONLY: "1" });
    const b = await ensureUpstreamLookupOptions({ PROXY_MCP_UPSTREAM_IPV4_ONLY: "1" });
    assert.equal(a, b);
  });
});
