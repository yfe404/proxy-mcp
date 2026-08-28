import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TerminalInterceptor } from "../../src/interceptors/terminal.js";

/**
 * The upstream password lives in the server's environment so that a caller need
 * not put it in a tool call. interceptor_spawn passes the server environment to
 * the child, so without an explicit delete the caller could read it straight
 * back with `env`. This is the only assertion that catches someone later
 * re-adding a bare `...process.env` spread.
 */
describe("TerminalInterceptor child environment", () => {
  const CERT = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n";

  async function spawnAndRead(script: string): Promise<string> {
    const interceptor = new TerminalInterceptor();
    const { targetId } = await interceptor.activate({
      proxyPort: 1,
      certPem: CERT,
      certFingerprint: "test",
      command: process.execPath,
      args: ["-e", script],
    });
    // Poll rather than sleep a fixed amount; the child prints and exits at once.
    for (let i = 0; i < 100; i++) {
      const out = interceptor.getProcessOutput(targetId);
      if (out?.exited) return out.stdout;
      await new Promise((r) => setTimeout(r, 20));
    }
    throw new Error("child did not exit in time");
  }

  it("does not pass the upstream password to a spawned process", async () => {
    process.env.PROXY_MCP_UPSTREAM_PASSWORD = "TOPSECRETPW";
    try {
      const stdout = await spawnAndRead(
        "console.log(process.env.PROXY_MCP_UPSTREAM_PASSWORD ?? 'ABSENT')",
      );
      assert.equal(stdout.trim(), "ABSENT");
      assert.ok(!stdout.includes("TOPSECRETPW"));
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_PASSWORD;
    }
  });

  it("still passes the upstream host, which is configuration not a secret", async () => {
    process.env.PROXY_MCP_UPSTREAM_HOST = "pinned.example";
    try {
      const stdout = await spawnAndRead(
        "console.log(process.env.PROXY_MCP_UPSTREAM_HOST ?? 'ABSENT')",
      );
      assert.equal(stdout.trim(), "pinned.example");
    } finally {
      delete process.env.PROXY_MCP_UPSTREAM_HOST;
    }
  });
});
