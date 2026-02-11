import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { ProxyManager } from "../../src/state.js";

describe("ProxyManager", () => {
  let pm: ProxyManager;

  afterEach(async () => {
    // Ensure cleanup
    if (pm?.isRunning()) {
      await pm.stop();
    }
  });

  it("starts and stops proxy", async (t) => {
    pm = new ProxyManager();
    assert.equal(pm.isRunning(), false);

    let result;
    try {
      result = await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    assert.equal(pm.isRunning(), true);
    assert.ok(result.port > 0);
    assert.ok(result.cert.fingerprint.length > 0);
    assert.ok(result.cert.cert.includes("BEGIN CERTIFICATE"));

    await pm.stop();
    assert.equal(pm.isRunning(), false);
  });

  it("rejects double start", async (t) => {
    pm = new ProxyManager();
    try {
      await pm.start(0);
    } catch (e: any) {
      if (e && (e.code === "EPERM" || e.code === "EACCES")) {
        t.skip("listen() not permitted in this environment");
        return;
      }
      throw e;
    }
    await assert.rejects(() => pm.start(0), /already running/);
  });

  it("rejects stop when not running", async () => {
    pm = new ProxyManager();
    await assert.rejects(() => pm.stop(), /not running/);
  });

  it("manages upstream proxy config", async () => {
    pm = new ProxyManager();
    assert.equal(pm.getGlobalUpstream(), null);

    await pm.setGlobalUpstream({ proxyUrl: "socks5://localhost:1080" });
    assert.deepEqual(pm.getGlobalUpstream(), { proxyUrl: "socks5://localhost:1080" });

    await pm.clearGlobalUpstream();
    assert.equal(pm.getGlobalUpstream(), null);
  });

  it("manages host upstream overrides", async () => {
    pm = new ProxyManager();
    await pm.setHostUpstream("example.com", { proxyUrl: "http://proxy:8080" });
    assert.equal(pm.getHostUpstreams().size, 1);

    const removed = await pm.removeHostUpstream("example.com");
    assert.equal(removed, true);
    assert.equal(pm.getHostUpstreams().size, 0);

    const removedAgain = await pm.removeHostUpstream("example.com");
    assert.equal(removedAgain, false);
  });

  it("manages interception rules CRUD", async () => {
    pm = new ProxyManager();
    const rule = await pm.addRule({
      priority: 10,
      enabled: true,
      description: "Test rule",
      matcher: { hostname: "example.com" },
      handler: { type: "mock", status: 200, body: "ok" },
    });

    assert.ok(rule.id.startsWith("rule_"));
    assert.equal(rule.hitCount, 0);

    const rules = pm.listRules();
    assert.equal(rules.length, 1);
    assert.equal(rules[0].description, "Test rule");

    await pm.updateRule(rule.id, { description: "Updated" });
    assert.equal(pm.getRule(rule.id)!.description, "Updated");

    await pm.disableRule(rule.id);
    assert.equal(pm.getRule(rule.id)!.enabled, false);

    await pm.enableRule(rule.id);
    assert.equal(pm.getRule(rule.id)!.enabled, true);

    const removed = await pm.removeRule(rule.id);
    assert.equal(removed, true);
    assert.equal(pm.listRules().length, 0);
  });

  it("manages traffic buffer", () => {
    pm = new ProxyManager();
    assert.equal(pm.getTraffic().length, 0);

    const cleared = pm.clearTraffic();
    assert.equal(cleared, 0);
  });

  it("searches traffic", () => {
    pm = new ProxyManager();
    // Empty search should return empty
    const results = pm.searchTraffic("test");
    assert.equal(results.length, 0);
  });

  it("evaluates rules with detailed diagnostics and disabled handling", async () => {
    pm = new ProxyManager();

    const disabledRule = await pm.addRule({
      priority: 5,
      enabled: false,
      description: "Disabled but matching",
      matcher: { method: "GET", hostname: "example.com" },
      handler: { type: "drop" },
    });
    const enabledRule = await pm.addRule({
      priority: 10,
      enabled: true,
      description: "Enabled winner",
      matcher: { method: "GET", hostname: "example.com" },
      handler: { type: "mock", status: 200, body: "ok" },
    });

    const withDisabled = pm.testRulesAgainstRequest({
      method: "GET",
      url: "https://example.com/path?q=1",
      headers: { accept: "*/*" },
      body: "",
    }, { includeDisabled: true });

    assert.equal(withDisabled.results.length, 2);
    assert.equal(withDisabled.matchedCount, 2);
    const disabledEval = withDisabled.results.find((r) => r.ruleId === disabledRule.id)!;
    assert.equal(disabledEval.matched, true);
    assert.equal(disabledEval.eligible, false);
    assert.equal(withDisabled.effectiveWinner?.ruleId, enabledRule.id);

    const withoutDisabled = pm.testRulesAgainstRequest({
      method: "GET",
      url: "https://example.com/path?q=1",
    }, { includeDisabled: false });
    assert.equal(withoutDisabled.results.length, 1);
    assert.equal(withoutDisabled.results[0].ruleId, enabledRule.id);
    assert.equal(withoutDisabled.effectiveWinner?.ruleId, enabledRule.id);
  });

  it("applies pathPattern parity in rule testing", async () => {
    pm = new ProxyManager();
    await pm.addRule({
      priority: 1,
      enabled: true,
      description: "Path constrained",
      matcher: { pathPattern: "^/api/" },
      handler: { type: "passthrough" },
    });

    const match = pm.testRulesAgainstRequest({
      url: "https://example.com/api/items",
    });
    assert.equal(match.effectiveWinner?.description, "Path constrained");
    assert.equal(match.results[0].checks.pathPattern.passed, true);

    const noMatch = pm.testRulesAgainstRequest({
      url: "https://example.com/healthz",
    });
    assert.equal(noMatch.effectiveWinner, null);
    assert.equal(noMatch.results[0].checks.pathPattern.passed, false);
  });

  it("throws for missing exchange when testing rules against exchange", () => {
    pm = new ProxyManager();
    assert.throws(
      () => pm.testRulesAgainstExchange("missing_exchange"),
      /not found/i,
    );
  });
});
