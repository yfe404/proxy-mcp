import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";

import { ProxyManager } from "../../src/state.js";
import { interceptorManager } from "../../src/interceptors/manager.js";
import type { ActivateResult, Interceptor, InterceptorMetadata } from "../../src/interceptors/types.js";

/**
 * Regression for #26.1, through ProxyManager.stop().
 *
 * proxyManager is a process singleton whose stop() called deactivateAll(), so
 * in HTTP mode one client's proxy_stop closed every other MCP session's
 * browsers. stop() now scopes the teardown to the calling session unless it is
 * asked for all of them.
 *
 * A fake interceptor stands in for the browser: it registers under an id of
 * its own, so the real terminal/browser/docker instances are untouched.
 */
class FakeInterceptor implements Interceptor {
  readonly id = "test-fake";
  readonly name = "Fake";
  readonly launched: string[] = [];
  private next = 0;

  async isActivable(): Promise<boolean> {
    return true;
  }

  async activate(): Promise<ActivateResult> {
    const targetId = `target_${this.next++}`;
    this.launched.push(targetId);
    return { targetId, details: {} };
  }

  async deactivate(targetId: string): Promise<void> {
    const i = this.launched.indexOf(targetId);
    if (i !== -1) this.launched.splice(i, 1);
  }

  async deactivateAll(): Promise<void> {
    this.launched.length = 0;
  }

  async getMetadata(): Promise<InterceptorMetadata> {
    return { id: this.id, name: this.name, description: "fake", isActivable: true, activeTargets: [] };
  }
}

const fake = new FakeInterceptor();
interceptorManager.register(fake);
const options = { proxyPort: 1, certPem: "", certFingerprint: "" };

describe("proxy_stop teardown scope", () => {
  let pm: ProxyManager | undefined;

  afterEach(async () => {
    if (pm?.isRunning()) await pm.stop({ allTargets: true });
    pm = undefined;
    await fake.deactivateAll();
  });

  async function startProxy(t: { skip: (why: string) => void }): Promise<boolean> {
    pm = new ProxyManager();
    try {
      await pm.start(0);
      return true;
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return false;
      }
      throw e;
    }
  }

  it("deactivates only the calling session's targets", async (t) => {
    if (!await startProxy(t)) return;

    const a = await interceptorManager.activate("test-fake", options, "session-a");
    const b = await interceptorManager.activate("test-fake", options, "session-b");

    await pm!.stop({ ownerSessionId: "session-a" });

    assert.deepEqual(fake.launched, [b.targetId], "session B's target must survive session A's proxy_stop");
    assert.equal(interceptorManager.ownerOf("test-fake", a.targetId), undefined);
    assert.equal(interceptorManager.ownerOf("test-fake", b.targetId), "session-b");
  });

  it("deactivates every session's targets when asked for all", async (t) => {
    if (!await startProxy(t)) return;

    await interceptorManager.activate("test-fake", options, "session-a");
    await interceptorManager.activate("test-fake", options, "session-b");

    await pm!.stop({ ownerSessionId: "session-a", allTargets: true });

    assert.deepEqual(fake.launched, []);
  });

  it("stays process-wide without a session id (stdio)", async (t) => {
    if (!await startProxy(t)) return;

    await interceptorManager.activate("test-fake", options, "session-a");
    await interceptorManager.activate("test-fake", options);

    await pm!.stop();

    assert.deepEqual(fake.launched, []);
  });
});
