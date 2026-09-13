import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { initInterceptors } from "../../src/interceptors/init.js";
import { InterceptorManager, interceptorManager } from "../../src/interceptors/manager.js";
import type { ActivateResult, Interceptor, InterceptorMetadata } from "../../src/interceptors/types.js";

/**
 * Regression for #25.
 *
 * The HTTP transport builds a fresh McpServer per MCP session. Registration of
 * tools per session is fine, but the interceptor registry is a process
 * singleton holding live browser handles: re-running initInterceptors() on the
 * second session replaced the BrowserInterceptor with an empty one and the
 * browsers launched by the first session became unreachable.
 *
 * No real browser is launched here — a fake carries the state a launched
 * target would.
 */

/**
 * Stands in for an interceptor holding live targets.
 *
 * It takes a real interceptor id deliberately: re-registering under `browser`
 * is exactly the overwrite that lost `launched` — the reported failure.
 */
class FakeInterceptor implements Interceptor {
  readonly id: string;
  readonly name = "Fake interceptor";
  readonly launched: string[] = [];

  constructor(id: string) {
    this.id = id;
  }

  async isActivable(): Promise<boolean> {
    return true;
  }

  async activate(): Promise<ActivateResult> {
    const targetId = `${this.id}_${this.launched.length}`;
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
    return {
      id: this.id,
      name: this.name,
      description: "fake",
      isActivable: true,
      activeTargets: [],
    };
  }
}

/** Mirrors the registrations in src/interceptors/init.ts. */
const REGISTERED_IDS = [
  "terminal",
  "browser",
  "docker",
];

describe("interceptor registry across MCP sessions", () => {
  it("keeps the same interceptor instances when a second session initialises", async () => {
    // Session A starts: index.ts createMcpServer() calls initInterceptors().
    initInterceptors();
    for (const id of REGISTERED_IDS) {
      assert.ok(interceptorManager.get(id), `${id} should be registered after the first init`);
    }
    const sessionA = new Map(REGISTERED_IDS.map((id) => [id, interceptorManager.get(id)]));

    // Session B starts in the same process.
    initInterceptors();

    // Every interceptor is the very same object — initInterceptors did not
    // re-register, so no live handle was dropped.
    for (const [id, interceptor] of sessionA) {
      assert.equal(interceptorManager.get(id), interceptor, `${id} was replaced by the second init`);
    }
  });

  /**
   * #26: the #25 fix guards initInterceptors(), the single call site. Making
   * register() itself refuse a duplicate makes the invariant structural, so no
   * future call site can silently orphan a live target.
   */
  it("refuses to re-register an id instead of dropping the live instance", async () => {
    initInterceptors();
    const registered = interceptorManager.get("browser");
    assert.ok(registered);

    assert.throws(
      () => interceptorManager.register(new FakeInterceptor("browser")),
      /already registered/,
    );

    // The original instance, and everything it holds, is untouched.
    assert.equal(interceptorManager.get("browser"), registered);
  });
});

/**
 * Regression for #26.1.
 *
 * proxyManager is a process singleton and its stop() called deactivateAll(),
 * so in HTTP mode one client's proxy_stop closed the browsers launched by
 * every other MCP session. Targets now record the session that activated them.
 *
 * A private manager instance keeps the singleton's real interceptors out of it.
 */
describe("interceptor ownership per MCP session", () => {
  const options = { proxyPort: 1, certPem: "", certFingerprint: "" };

  function twoSessionSetup() {
    const manager = new InterceptorManager();
    const browser = new FakeInterceptor("browser");
    const docker = new FakeInterceptor("docker");
    manager.register(browser);
    manager.register(docker);
    return { manager, browser, docker };
  }

  it("records the activating session and deactivates only that session's targets", async () => {
    const { manager, browser, docker } = twoSessionSetup();

    const a = await manager.activate("browser", options, "session-a");
    const b = await manager.activate("browser", options, "session-b");
    const dockerB = await manager.activate("docker", options, "session-b");

    assert.equal(manager.ownerOf("browser", a.targetId), "session-a");
    assert.equal(manager.ownerOf("browser", b.targetId), "session-b");

    const deactivated = await manager.deactivateOwnedBy("session-a");

    assert.equal(deactivated, 1);
    assert.deepEqual(browser.launched, [b.targetId], "session B's browser must survive session A's stop");
    assert.deepEqual(docker.launched, [dockerB.targetId], "session B's container must survive too");
    assert.equal(manager.ownerOf("browser", a.targetId), undefined);
  });

  it("leaves stdio targets (no session id) running when one session stops", async () => {
    const { manager, browser } = twoSessionSetup();

    const stdio = await manager.activate("browser", options);
    const owned = await manager.activate("browser", options, "session-a");
    assert.equal(manager.ownerOf("browser", stdio.targetId), undefined);

    await manager.deactivateOwnedBy("session-a");
    assert.deepEqual(browser.launched, [stdio.targetId]);

    // deactivateAll stays process-wide: it is what stdio and `all: true` use.
    await manager.deactivateAll();
    assert.deepEqual(browser.launched, []);
    assert.equal(manager.ownerOf("browser", owned.targetId), undefined);
  });

  it("forgets the owner when a target is deactivated by id", async () => {
    const { manager } = twoSessionSetup();
    const a = await manager.activate("browser", options, "session-a");

    await manager.deactivate("browser", a.targetId);

    assert.equal(manager.ownerOf("browser", a.targetId), undefined);
    assert.equal(await manager.deactivateOwnedBy("session-a"), 0);
  });
});
