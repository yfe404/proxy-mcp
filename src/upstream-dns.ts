/**
 * IPv4-only upstream DNS resolution for mockttp's passthrough rules.
 *
 * Observed on the Apify platform: in a container that has no IPv6 route,
 * mockttp's passthrough opened upstream connections over IPv6 and failed them
 * with `connect ENETUNREACH 2606:4700::…:443`, a handful of requests per page.
 * `NODE_OPTIONS=--dns-result-order=ipv4first` on the server process did not
 * change it.
 *
 * Measured cause (platform A/B, 2026-09-13): every one of those errors came
 * from `brunhild.challenges.cloudflare.com`, a Cloudflare challenge host that
 * publishes AAAA records and no A record. Node was not mis-ordering a
 * dual-stack answer, so result order could not help — there was no IPv4
 * address to pick. Constraining the resolver therefore does not make that host
 * reachable; the request fails as `getaddrinfo ENOTFOUND` instead. What it
 * does guarantee is that a host publishing both A and AAAA records is always
 * reached over IPv4 and can never stall on an unroutable address.
 *
 * mockttp 3.17's public `lookupOptions` only carries cacheable-lookup settings
 * (`maxTtl`, `errorTtl`, `servers`) — it has no hook for supplying a lookup
 * function. `getDnsLookupFunction` is a lodash-memoised export keyed on the
 * `lookupOptions` object, so the least invasive hook available is to seed that
 * memo cache with our own function under a private token object and pass that
 * token as `lookupOptions` on our passthrough rules. Nothing else in the
 * process is affected, and if the internals ever move we fall back to
 * mockttp's own resolver rather than changing behaviour silently.
 *
 * Off switch: PROXY_MCP_UPSTREAM_IPV4_ONLY=0 (also false/no/off).
 *
 * Trade-off: with the flag on, a host that publishes only AAAA records becomes
 * unreachable through the proxy even where IPv6 works. That is the intended
 * exchange on IPv4-only infrastructure, and it is why the flag exists.
 */

import dns from "node:dns";
import type { PassThroughLookupOptions } from "mockttp/dist/rules/passthrough-handling-definitions";

/** `dns.lookup`'s shape, narrowed to the call we make. */
export type RawDnsLookup = (
  hostname: string,
  options: dns.LookupAllOptions | dns.LookupOneOptions,
  callback: (err: NodeJS.ErrnoException | null, ...rest: never[]) => void,
) => void;

/**
 * mockttp calls the lookup function both ways: `http.request` passes
 * `(hostname, options, callback)`, while mockttp's own `dnsLookup` helper
 * passes `(hostname, callback)`.
 */
export type UpstreamLookup = (...args: unknown[]) => void;

const DEFAULT_CACHE_MS = 10_000;
const OFF_VALUES = new Set(["0", "false", "no", "off"]);

/** Reads the PROXY_MCP_UPSTREAM_IPV4_ONLY flag. Defaults to on. */
export function isUpstreamIpv4OnlyEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.PROXY_MCP_UPSTREAM_IPV4_ONLY;
  if (raw === undefined) return true;
  const normalised = raw.trim().toLowerCase();
  if (normalised === "") return true;
  return !OFF_VALUES.has(normalised);
}

/**
 * A `dns.lookup`-compatible function that answers with A records only.
 *
 * Successful answers are cached briefly, mirroring the 10s cache mockttp
 * applies by default, so replacing its resolver does not add a resolver round
 * trip per upstream request. Failures are never cached.
 */
export function createIpv4OnlyLookup(deps: { lookup?: RawDnsLookup; cacheMs?: number } = {}): UpstreamLookup {
  const rawLookup = deps.lookup ?? (dns.lookup as unknown as RawDnsLookup);
  const cacheMs = deps.cacheMs ?? DEFAULT_CACHE_MS;
  const cache = new Map<string, unknown[]>();

  return (...args: unknown[]) => {
    const hostname = args[0] as string;
    const callback = args[args.length - 1] as (...cbArgs: unknown[]) => void;
    const callerOptions = (args.length > 2 ? args[1] : undefined) as Record<string, unknown> | undefined;

    // family: 4 is the whole point; everything else the caller asked for
    // (all, hints, verbatim) is preserved so the callback shape still matches
    // what the caller expects.
    const options: Record<string, unknown> = { ...(callerOptions ?? {}), family: 4 };

    const key = `${hostname}|${options.all ? 1 : 0}|${String(options.hints ?? 0)}`;
    const cached = cache.get(key);
    if (cached) {
      setImmediate(() => callback(null, ...cached));
      return;
    }

    rawLookup(hostname, options as unknown as dns.LookupAllOptions, (err, ...rest) => {
      if (!err && cacheMs > 0) {
        cache.set(key, rest);
        setTimeout(() => cache.delete(key), cacheMs).unref();
      }
      callback(err, ...rest);
    });
  };
}

/**
 * Private token passed to mockttp as `lookupOptions`. Its only job is to be a
 * stable object identity that `getDnsLookupFunction`'s memo cache maps to
 * `createIpv4OnlyLookup()`. It is deliberately empty: if the seeding below
 * ever fails we must not hand mockttp a token it would interpret as real
 * cacheable-lookup settings, so `upstreamLookupOptions` returns undefined in
 * that case instead.
 */
const IPV4_LOOKUP_TOKEN: PassThroughLookupOptions = {};

let seeded: "pending" | "ok" | "failed" = "pending";

/**
 * The `lookupOptions` value to pass to mockttp passthrough/forward rules, or
 * undefined to leave mockttp's default resolver in place (flag off, or the
 * mockttp internals this depends on are not where we expect them).
 */
export async function upstreamLookupOptions(
  env: NodeJS.ProcessEnv = process.env,
): Promise<PassThroughLookupOptions | undefined> {
  if (!isUpstreamIpv4OnlyEnabled(env)) return undefined;
  if (seeded === "failed") return undefined;
  if (seeded === "ok") return IPV4_LOOKUP_TOKEN;

  try {
    const { getDnsLookupFunction } = await import("mockttp/dist/rules/passthrough-handling");
    const memo = getDnsLookupFunction as unknown as { cache?: { set?: (k: unknown, v: unknown) => void } };
    if (typeof memo.cache?.set !== "function") throw new Error("getDnsLookupFunction is not memoised");

    const lookup = createIpv4OnlyLookup();
    memo.cache.set(IPV4_LOOKUP_TOKEN, lookup);
    if (getDnsLookupFunction(IPV4_LOOKUP_TOKEN) !== (lookup as unknown)) {
      throw new Error("seeding getDnsLookupFunction did not take effect");
    }
    seeded = "ok";
    console.error("[proxy-mcp] upstream DNS resolution constrained to IPv4 (PROXY_MCP_UPSTREAM_IPV4_ONLY).");
    return IPV4_LOOKUP_TOKEN;
  } catch (e) {
    seeded = "failed";
    console.error(
      "[proxy-mcp] PROXY_MCP_UPSTREAM_IPV4_ONLY is on but mockttp's DNS lookup could not be " +
      `constrained to IPv4; upstream resolution is unchanged. Reason: ${String(e)}`,
    );
    return undefined;
  }
}
