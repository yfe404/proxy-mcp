import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parse } from "node:url";
import { truncateResult, getLocalIP, serializeHeaders, capString, redactProxyUrl, mergeUpstreamPassword, upstreamPasswordSource, spawnEnv } from "../../src/utils.js";

describe("truncateResult", () => {
  it("returns short data unchanged", () => {
    const data = { foo: "bar" };
    const result = truncateResult(data);
    assert.equal(result, JSON.stringify(data));
  });

  it("truncates large arrays with binary search", () => {
    const data = Array.from({ length: 5000 }, (_, i) => ({ id: i, value: "x".repeat(100) }));
    const result = truncateResult(data);
    const parsed = JSON.parse(result);
    assert.equal(parsed.truncated, true);
    assert.ok(parsed.showing < 5000);
    assert.equal(parsed.total, 5000);
    assert.ok(result.length <= 24000);
  });

  it("truncates large strings", () => {
    const data = "x".repeat(30000);
    const result = truncateResult(data);
    assert.ok(result.length <= 24000);
    assert.ok(result.includes("[truncated"));
  });
});

describe("getLocalIP", () => {
  it("returns a valid IP string", () => {
    const ip = getLocalIP();
    assert.ok(typeof ip === "string");
    assert.ok(ip.length > 0);
  });
});

describe("serializeHeaders", () => {
  it("lowercases keys and joins arrays", () => {
    const headers = {
      "Content-Type": "application/json",
      "X-Custom": ["a", "b"],
      "X-Undefined": undefined,
    };
    const result = serializeHeaders(headers);
    assert.equal(result["content-type"], "application/json");
    assert.equal(result["x-custom"], "a, b");
    assert.ok(!("x-undefined" in result));
  });
});

describe("capString", () => {
  it("returns short strings unchanged", () => {
    assert.equal(capString("hello", 10), "hello");
  });

  it("truncates long strings with ellipsis", () => {
    assert.equal(capString("hello world", 5), "hello...");
  });
});

describe("redactProxyUrl", () => {
  it("redacts the password and keeps the username", () => {
    assert.equal(
      redactProxyUrl("http://user:s3cret@proxy.example.com:8000"),
      "http://user:***@proxy.example.com:8000/",
    );
  });

  it("keeps a username that encodes configuration", () => {
    assert.equal(
      redactProxyUrl("http://groups-RESIDENTIAL,country-US:apify_proxy_abc@proxy.apify.com:8000"),
      "http://groups-RESIDENTIAL,country-US:***@proxy.apify.com:8000/",
    );
  });

  it("leaves a URL without a password alone", () => {
    assert.equal(redactProxyUrl("http://proxy.example.com:8000"), "http://proxy.example.com:8000/");
    assert.equal(redactProxyUrl("http://user@proxy.example.com:8000"), "http://user@proxy.example.com:8000/");
  });

  it("treats an empty password (user:@host) as no password", () => {
    // The WHATWG parser erases the empty password before redaction sees it,
    // so there is nothing to mask and no stray ":***" appears.
    assert.equal(
      redactProxyUrl("http://user:@proxy.example.com:8000"),
      "http://user@proxy.example.com:8000/",
    );
  });

  it("drops a pac+http token carried in the query", () => {
    assert.equal(
      redactProxyUrl("pac+http://pac.example.com/proxy.pac?token=SECRET"),
      "pac+http://pac.example.com/***",
    );
  });

  it("drops a bare query token, which masking values alone would echo", () => {
    // "?SECRETTOKEN" has no "=", so it parses as a key with an empty value.
    // Masking values would return "?SECRETTOKEN=***": the token in full,
    // wearing the mask that is supposed to mean it is gone.
    for (const url of [
      "pac+http://pac.example.com/proxy.pac?SECRETTOKEN",
      "pac+http://h/p.pac?a=1&SECRETTOKEN",
      "http://u:pw@h:8000?SECRETTOKEN",
    ]) {
      assert.ok(!redactProxyUrl(url).includes("SECRETTOKEN"), url);
    }
  });

  it("masks path segments and drops the fragment", () => {
    // A PAC provider may carry its token in the path rather than the query, and
    // no agent in this stack reads the fragment. Neither is worth echoing.
    assert.equal(
      redactProxyUrl("pac+http://pac.example.com/AbC123token/proxy.pac"),
      "pac+http://pac.example.com/***/***",
    );
    assert.ok(!redactProxyUrl("http://u:p@host:8000/tok#frag").includes("frag"));
    // An authority-only URL has no path to mask.
    assert.equal(redactProxyUrl("http://host:8000"), "http://host:8000/");
  });

  it("redacts a password duplicated into the query", () => {
    assert.ok(!redactProxyUrl("http://u:SECRET@host:8000?dup=SECRET").includes("SECRET"));
  });

  it("handles socks and pac schemes", () => {
    assert.equal(redactProxyUrl("socks5://user:pass@host:1080"), "socks5://user:***@host:1080");
    assert.equal(redactProxyUrl("socks4://host:1080"), "socks4://host:1080");
    assert.equal(
      redactProxyUrl("pac+http://example.com/proxy.pac"),
      "pac+http://example.com/***",
    );
  });

  it("redacts percent-encoded credentials", () => {
    assert.equal(
      redactProxyUrl("http://us%40er:p%3Aass@host:8000"),
      "http://us%40er:***@host:8000/",
    );
  });

  it("reduces an opaque-path URL to its scheme", () => {
    // "pac+http:host/TOKEN.pac" has no authority, so assigning pathname is a
    // silent no-op and the token would otherwise survive verbatim.
    assert.equal(redactProxyUrl("pac+http:host/TOKEN.pac"), "pac+http:***");
    assert.ok(!redactProxyUrl("pac+http:host/TOKEN.pac").includes("TOKEN"));
  });

  it("never echoes an unparseable value", () => {
    assert.equal(redactProxyUrl("not a url"), "<unparseable url>");
    assert.equal(redactProxyUrl(""), "<unparseable url>");
  });
});

describe("mergeUpstreamPassword", () => {
  const env = { PROXY_MCP_UPSTREAM_PASSWORD: "s3cret", PROXY_MCP_UPSTREAM_HOST: "host" };
  const at = (hostname: string) => ({
    PROXY_MCP_UPSTREAM_PASSWORD: "s3cret",
    PROXY_MCP_UPSTREAM_HOST: hostname,
  });

  it("sends the password only to the pinned host", () => {
    // The password must not be deliverable to a host the caller picks: that is
    // exfiltration by delivery, which redaction cannot see.
    const out = mergeUpstreamPassword("http://x@attacker.example:8000", at("proxy.apify.com"));
    assert.equal(out, "http://x@attacker.example:8000");
    assert.equal(new URL(out).password, "");
  });

  it("matches the host case-insensitively and ignores the port", () => {
    assert.equal(
      new URL(mergeUpstreamPassword("http://u@Proxy.Example:9000", at("proxy.example"))).password,
      "s3cret",
    );
  });

  it("fails closed when the host variable is unset", () => {
    // A half-configuration must not degrade into an unbound credential.
    assert.equal(
      mergeUpstreamPassword("http://u@host:8000", { PROXY_MCP_UPSTREAM_PASSWORD: "s3cret" }),
      "http://u@host:8000",
    );
  });

  it("fills the password slot of a username-only URL", () => {
    assert.equal(
      mergeUpstreamPassword("http://groups-RESIDENTIAL,country-US@proxy.apify.com:8000", at("proxy.apify.com")),
      "http://groups-RESIDENTIAL,country-US:s3cret@proxy.apify.com:8000/",
    );
  });

  it("puts the secret nowhere but the password slot", () => {
    const out = mergeUpstreamPassword("http://user@host:8000/path?q=1", env);
    const url = new URL(out);
    assert.equal(url.password, "s3cret");
    assert.equal(url.username, "user");
    assert.equal(url.host, "host:8000");
    assert.equal(url.pathname, "/path");
    assert.equal(url.search, "?q=1");
  });

  it("percent-encodes a password that would otherwise re-point the upstream", () => {
    const out = mergeUpstreamPassword("http://user@host:8000", {
      PROXY_MCP_UPSTREAM_PASSWORD: "p@evil.example:80/",
      PROXY_MCP_UPSTREAM_HOST: "host",
    });
    assert.equal(new URL(out).host, "host:8000");
    assert.ok(!out.includes("@evil.example"));
  });

  it("survives mockttp's url.parse().auth round-trip", () => {
    // mockttp reads credentials via legacy url.parse().auth (rules/http-agents.js:57),
    // which percent-decodes. Encoding here must therefore be lossless, or a
    // password containing "@" or "/" would authenticate with the wrong value.
    // ":" is excluded deliberately — see the socks test below.
    const secret = "p@ss/word#with?specials";
    const out = mergeUpstreamPassword("http://user@host:8000", {
      PROXY_MCP_UPSTREAM_PASSWORD: secret,
      PROXY_MCP_UPSTREAM_HOST: "host",
    });
    assert.equal(parse(out).auth, `user:${secret}`);
    assert.equal(new URL(out).host, "host:8000");
  });

  it("survives the round-trip with a '%' in the password", () => {
    // The password setter escapes "@" and "/" but not "%", while url.parse()
    // decodeURIComponent()s the auth: a raw "%" made that decode throw, and a
    // raw "%20" decoded to a space. Both must come back byte-identical.
    for (const secret of ["100%pass", "p%20ss", "%"]) {
      const out = mergeUpstreamPassword("http://user@host:8000", {
        PROXY_MCP_UPSTREAM_PASSWORD: secret,
        PROXY_MCP_UPSTREAM_HOST: "host",
      });
      assert.equal(parse(out).auth, `user:${secret}`);
    }
  });

  it("reaches https-proxy-agent intact, including a ':' in the password", () => {
    // https-proxy-agent takes the whole auth string, so ":" is safe here.
    const secret = "pa:ss/word";
    const out = mergeUpstreamPassword("https://user@host:8443", {
      PROXY_MCP_UPSTREAM_PASSWORD: secret,
      PROXY_MCP_UPSTREAM_HOST: "host",
    });
    const auth = parse(out).auth!;
    assert.equal(auth.slice(auth.indexOf(":") + 1), secret);
  });

  it("refuses a socks upstream rather than truncate the password at ':'", () => {
    // socks-proxy-agent@7 does opts.auth.split(":") and takes [1]
    // (mockttp/node_modules/socks-proxy-agent/dist/index.js:78-81), so anything
    // after the first ":" is silently dropped and half the password
    // authenticates. Refusing is better than delivering a credential we know is
    // wrong. A literal socks5://u:pa%3Ass@host still truncates — the toolchain
    // limit is unchanged, this only stops us walking into it.
    assert.throws(
      () => mergeUpstreamPassword("socks5://user@host:1080", {
        PROXY_MCP_UPSTREAM_PASSWORD: "pa:ss",
        PROXY_MCP_UPSTREAM_HOST: "host",
      }),
      /truncates/,
    );
    assert.equal(parse("socks5://user:pa%3Ass@host:1080").auth!.split(":")[1], "pa");

    // ...while a socks password with no ":" is delivered whole.
    const ok = mergeUpstreamPassword("socks5://user@host:1080", {
      PROXY_MCP_UPSTREAM_PASSWORD: "p@ss/word",
      PROXY_MCP_UPSTREAM_HOST: "host",
    });
    assert.equal(parse(ok).auth!.split(":")[1], "p@ss/word");

    // http takes the whole password, so ":" is fine there.
    assert.equal(
      parse(mergeUpstreamPassword("http://user@host:8000", {
        PROXY_MCP_UPSTREAM_PASSWORD: "pa:ss",
        PROXY_MCP_UPSTREAM_HOST: "host",
      })).auth,
      "user:pa:ss",
    );
  });

  it("refuses a ':' in the username on every scheme", () => {
    // Basic auth splits the decoded pair at the first colon (RFC 7617) and
    // socks-proxy-agent does the same, so "gro:ups" + "s3cret" arrives as user
    // "gro" / password "ups:s3cret" — the merged password is discarded while
    // the tool would still report passwordSource: "env". http is NOT exempt:
    // checking url.parse().auth alone makes it look harmless, which is one
    // layer short of what the proxy actually reads.
    for (const url of [
      "socks5://gro%3Aups@host:1080",
      "http://gro%3Aups@host:8000",
      "https://gro%3Aups@host:8443",
    ]) {
      assert.throws(
        () => mergeUpstreamPassword(url, {
          PROXY_MCP_UPSTREAM_PASSWORD: "s3cret",
          PROXY_MCP_UPSTREAM_HOST: "host",
        }),
        /separator/,
        url,
      );
    }
  });

  it("accepts a '%' in the username", () => {
    // The check must be a regex on "%3A", not decodeURIComponent(): the WHATWG
    // userinfo encode set leaves "%" alone, so "100%pass" survives verbatim and
    // decoding it throws URIError. A literal ":" can never reach url.username,
    // so the regex is total.
    for (const user of ["100%pass", "50%off", "user%"]) {
      const out = mergeUpstreamPassword(`http://${user}@host:8000`, {
        PROXY_MCP_UPSTREAM_PASSWORD: "s3cret",
        PROXY_MCP_UPSTREAM_HOST: "host",
      });
      assert.equal(new URL(out).password, "s3cret", user);
      assert.equal(new URL(out).username, user);
    }
  });

  it("leaves an explicit password alone", () => {
    assert.equal(
      mergeUpstreamPassword("http://user:mine@host:8000", env),
      "http://user:mine@host:8000",
    );
  });

  it("matches an IPv6 upstream, whose hostname carries brackets", () => {
    // url.hostname returns "[::1]", so a bare "::1" in the variable — the form
    // the README documents — would never match without normalizing.
    for (const pinned of ["::1", "[::1]"]) {
      const out = mergeUpstreamPassword("http://user@[::1]:8000", {
        PROXY_MCP_UPSTREAM_PASSWORD: "s3cret",
        PROXY_MCP_UPSTREAM_HOST: pinned,
      });
      assert.equal(new URL(out).password, "s3cret", `pinned as ${pinned}`);
      assert.equal(new URL(out).hostname, "[::1]");
    }
  });

  it("still refuses a different IPv6 host", () => {
    assert.equal(
      mergeUpstreamPassword("http://user@[::2]:8000", {
        PROXY_MCP_UPSTREAM_PASSWORD: "s3cret",
        PROXY_MCP_UPSTREAM_HOST: "::1",
      }),
      "http://user@[::2]:8000",
    );
  });

  it("leaves a URL with no username alone", () => {
    assert.equal(mergeUpstreamPassword("http://host:8000", env), "http://host:8000");
  });

  it("is a no-op when the variable is unset", () => {
    assert.equal(mergeUpstreamPassword("http://user@host:8000", {}), "http://user@host:8000");
  });

  it("returns an unparseable URL untouched for the caller to reject", () => {
    assert.equal(mergeUpstreamPassword("not a url", env), "not a url");
  });
});

describe("upstreamPasswordSource", () => {
  const env = { PROXY_MCP_UPSTREAM_PASSWORD: "s3cret", PROXY_MCP_UPSTREAM_HOST: "host" };
  const source = (url: string, e: NodeJS.ProcessEnv) =>
    upstreamPasswordSource(url, mergeUpstreamPassword(url, e));

  it("reports where the password came from", () => {
    assert.equal(source("http://user@host:8000", env), "env");
    assert.equal(source("http://user:mine@host:8000", env), "url");
    // The case worth reporting: the caller named a user, no password was
    // applied, so the upstream is about to be used username-only.
    assert.equal(source("http://user@host:8000", {}), "none");
    // No username, no question to answer — the field is omitted entirely
    // rather than warning about a correctly unauthenticated upstream.
    assert.equal(source("http://host:8000", env), null);
    assert.equal(source("not a url", env), null);
  });
});

describe("spawnEnv", () => {
  it("removes the upstream password", () => {
    process.env.PROXY_MCP_UPSTREAM_PASSWORD = "TOPSECRETPW";
    try {
      const env = spawnEnv();
      assert.ok(!("PROXY_MCP_UPSTREAM_PASSWORD" in env));
      assert.ok(!JSON.stringify(env).includes("TOPSECRETPW"));
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_PASSWORD;
    }
  });

  it("keeps the upstream host, which is configuration not a secret", () => {
    process.env.PROXY_MCP_UPSTREAM_HOST = "pinned.example";
    try {
      assert.equal(spawnEnv().PROXY_MCP_UPSTREAM_HOST, "pinned.example");
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_HOST;
    }
  });

  it("merges extras and still scrubs", () => {
    process.env.PROXY_MCP_UPSTREAM_PASSWORD = "TOPSECRETPW";
    try {
      const env = spawnEnv({ NO_COLOR: "1" });
      assert.equal(env.NO_COLOR, "1");
      assert.ok(!("PROXY_MCP_UPSTREAM_PASSWORD" in env));
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_PASSWORD;
    }
  });

  it("does not mutate process.env", () => {
    process.env.PROXY_MCP_UPSTREAM_PASSWORD = "TOPSECRETPW";
    try {
      spawnEnv();
      assert.equal(process.env.PROXY_MCP_UPSTREAM_PASSWORD, "TOPSECRETPW");
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_PASSWORD;
    }
  });
});
