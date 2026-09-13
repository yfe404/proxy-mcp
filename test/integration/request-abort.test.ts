import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";

import { ProxyManager } from "../../src/state.js";

/**
 * Regression for #29.
 *
 * A client that cancels an in-flight request (navigation away, page teardown)
 * made mockttp print `Failed to handle request: Aborted` per request; a normal
 * discover walk produced a dozen of them and they buried real upstream errors.
 * The proxy now reports each cancellation as one debug line naming the method
 * and URL, and mockttp's line is dropped.
 */
describe("client-aborted requests", () => {
  let pm: ProxyManager | undefined;
  const originalError = console.error;

  afterEach(async () => {
    console.error = originalError;
    if (pm?.isRunning()) await pm.stop();
    pm = undefined;
  });

  it("logs one debug line naming the method and URL, and no mockttp abort stack", async (t) => {
    const target = http.createServer(() => {
      // Never respond: the request stays in flight until the client goes away.
    });
    try {
      await new Promise<void>((resolve, reject) => {
        target.once("error", reject);
        target.listen(0, resolve);
      });
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    const targetPort = (target.address() as { port: number }).port;

    // Capture stderr before the proxy starts: ProxyManager installs the
    // mockttp log filter on top of whatever console.error is then.
    const logged: string[] = [];
    process.env.PROXY_MCP_DEBUG = "1";
    console.error = (...args: unknown[]) => {
      logged.push(args.map((a) => (a instanceof Error ? `${a.name}: ${a.message}` : String(a))).join(" "));
    };

    try {
      pm = new ProxyManager();
      let proxyPort: number;
      try {
        ({ port: proxyPort } = await pm.start(0));
      } catch (e: any) {
        if (e && (e.code === "EPERM" || e.code === "EACCES")) {
          t.skip("listen() not permitted in this environment");
          return;
        }
        throw e;
      }

      // A rule that rewrites the request body makes mockttp buffer it before
      // forwarding (waitForCompletedRequest), which is the exact condition
      // that produced the `Failed to handle request: Aborted` flood: the
      // browser sessions in #29 ran with body-transforming rules and JA3
      // spoofing, both of which take that path.
      await pm.addRule({
        priority: 1,
        enabled: true,
        description: "force request-body buffering",
        matcher: { hostname: "127.0.0.1" },
        handler: { type: "passthrough", transformRequest: { matchReplaceBody: [["nothing-matches", "x"]] } },
      });

      // Open a connection, send a partial request, close it: the declared body
      // never arrives, so mockttp's streamToBuffer rejects with Error('Aborted').
      const url = `http://127.0.0.1:${targetPort}/aborted`;
      await new Promise<void>((resolve, reject) => {
        const socket = net.connect(proxyPort, "127.0.0.1", () => {
          socket.write(
            `POST ${url} HTTP/1.1\r\n`
            + `Host: 127.0.0.1:${targetPort}\r\n`
            + "Content-Type: application/json\r\n"
            + "Content-Length: 512\r\n"
            + "\r\n"
            + '{"partial":',
          );
          // Give the proxy a moment to parse and start forwarding, then vanish.
          setTimeout(() => {
            socket.destroy();
            resolve();
          }, 150);
        });
        socket.on("error", reject);
      });

      const expected = `request aborted by client: POST ${url}`;
      await waitFor(() => logged.includes(expected), () =>
        `expected ${JSON.stringify(expected)} in stderr, saw ${JSON.stringify(logged)}`);

      // Exactly one line for the cancelled request, and nothing else about it:
      // neither mockttp's `Failed to handle request: Aborted`, nor the bare
      // Error('Aborted') its announce* handlers print with a full stack.
      assert.deepEqual(
        logged.filter((l) => l.includes("Aborted") || l.includes("aborted")),
        [expected],
      );
    } finally {
      delete process.env.PROXY_MCP_DEBUG;
      await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  });
});

async function waitFor(predicate: () => boolean, message: () => string, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  assert.fail(message());
}
