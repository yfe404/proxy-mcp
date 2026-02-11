/**
 * Interception rule tools — CRUD for traffic matching and handling rules.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import type { RuleHandler, RuleMatcher, RequestTransformConfig, ResponseTransformConfig } from "../state.js";
import { truncateResult } from "../utils.js";

const matcherSchema = z.object({
  method: z.string().optional().describe("HTTP method (GET, POST, etc.)"),
  urlPattern: z.string().optional().describe("Regex pattern to match against full URL"),
  hostname: z.string().optional().describe("Hostname to match"),
  pathPattern: z.string().optional().describe("Regex pattern for URL path"),
  headers: z.record(z.string()).optional().describe("Headers that must be present"),
  bodyIncludes: z.string().optional().describe("String that request body must contain"),
});

const requestTransformSchema = z.object({
  updateHeaders: z.record(z.string().nullable()).optional().describe("Headers to add/overwrite on request (set value to null to delete a header)"),
  replaceMethod: z.string().optional().describe("Replace HTTP method"),
  matchReplaceBody: z.array(z.tuple([z.string(), z.string()])).optional().describe("Array of [match, replace] pairs for body"),
}).optional();

const responseTransformSchema = z.object({
  updateHeaders: z.record(z.string().nullable()).optional().describe("Headers to add/overwrite on response (set value to null to delete a header)"),
  replaceStatus: z.number().optional().describe("Replace response status code"),
  matchReplaceBody: z.array(z.tuple([z.string(), z.string()])).optional().describe("Array of [match, replace] pairs for body"),
}).optional();

const handlerSchema = z.object({
  type: z.enum(["passthrough", "mock", "forward", "drop"]).describe("Handler type"),
  status: z.number().optional().describe("Response status (for mock)"),
  body: z.string().optional().describe("Response body (for mock)"),
  headers: z.record(z.string()).optional().describe("Response headers (for mock)"),
  forwardTo: z.string().optional().describe("Target host (for forward, e.g., http://other-server:3000)"),
  transformRequest: requestTransformSchema.describe("Request transform config"),
  transformResponse: responseTransformSchema.describe("Response transform config"),
});

const testRequestSchema = z.object({
  method: z.string().optional().default("GET").describe("HTTP method (default: GET)"),
  url: z.string().describe("Full request URL (required in simulate mode)"),
  hostname: z.string().optional().describe("Optional hostname override (default: derived from URL)"),
  path: z.string().optional().describe("Optional path override (default: derived from URL path + query)"),
  headers: z.record(z.string()).optional().describe("Request headers"),
  body: z.string().optional().default("").describe("Request body (default: empty)"),
});

export function registerRuleTools(server: McpServer): void {
  server.tool(
    "proxy_add_rule",
    "Add an interception rule with a matcher and handler. Rules are evaluated by priority (ascending), first match wins.",
    {
      description: z.string().describe("Human-readable description of this rule"),
      priority: z.number().optional().default(100).describe("Priority (lower = higher priority, default: 100)"),
      matcher: matcherSchema.describe("Conditions to match requests"),
      handler: handlerSchema.describe("What to do with matched requests"),
    },
    async ({ description, priority, matcher, handler }) => {
      try {
        const rule = await proxyManager.addRule({
          priority,
          enabled: true,
          description,
          matcher: matcher as RuleMatcher,
          handler: handler as RuleHandler,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", rule }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_update_rule",
    "Modify an existing interception rule.",
    {
      rule_id: z.string().describe("Rule ID to update"),
      description: z.string().optional().describe("New description"),
      priority: z.number().optional().describe("New priority"),
      matcher: matcherSchema.optional().describe("New matcher config"),
      handler: handlerSchema.optional().describe("New handler config"),
    },
    async ({ rule_id, description, priority, matcher, handler }) => {
      try {
        const updates: Record<string, unknown> = {};
        if (description !== undefined) updates.description = description;
        if (priority !== undefined) updates.priority = priority;
        if (matcher !== undefined) updates.matcher = matcher;
        if (handler !== undefined) updates.handler = handler;

        const rule = await proxyManager.updateRule(rule_id, updates);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", rule }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_remove_rule",
    "Delete an interception rule.",
    {
      rule_id: z.string().describe("Rule ID to delete"),
    },
    async ({ rule_id }) => {
      const removed = await proxyManager.removeRule(rule_id);
      if (!removed) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Rule '${rule_id}' not found` }) }] };
      }
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", message: `Rule '${rule_id}' removed.` }),
        }],
      };
    },
  );

  server.tool(
    "proxy_list_rules",
    "List all interception rules sorted by priority.",
    {},
    async () => {
      const rules = proxyManager.listRules();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", count: rules.length, rules }),
        }],
      };
    },
  );

  server.tool(
    "proxy_test_rule_match",
    "Test which interception rules would match a request, with detailed per-field pass/fail diagnostics and effective winner by priority.",
    {
      mode: z.enum(["simulate", "exchange"]).optional().default("simulate")
        .describe("simulate: test a synthetic request, exchange: test an existing captured exchange"),
      request: testRequestSchema.optional().describe("Synthetic request (required when mode=simulate)"),
      exchange_id: z.string().optional().describe("Exchange ID from proxy_list_traffic (required when mode=exchange)"),
      include_disabled: z.boolean().optional().default(true)
        .describe("Include disabled rules in diagnostics (default: true); disabled rules never win"),
      limit_rules: z.number().optional().describe("Optional limit on number of priority-sorted rules evaluated"),
    },
    async ({ mode, request, exchange_id, include_disabled, limit_rules }) => {
      try {
        const options = {
          includeDisabled: include_disabled,
          limitRules: limit_rules,
        };

        if (mode === "exchange") {
          if (!exchange_id) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({ status: "error", error: "exchange_id is required when mode='exchange'" }),
              }],
            };
          }
          const result = proxyManager.testRulesAgainstExchange(exchange_id, options);
          return {
            content: [{
              type: "text",
              text: truncateResult({
                status: "success",
                mode,
                exchange_id,
                result,
              }),
            }],
          };
        }

        if (!request) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: "request is required when mode='simulate'" }),
            }],
          };
        }

        const result = proxyManager.testRulesAgainstRequest(request, options);
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              mode,
              result,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_enable_rule",
    "Enable a disabled interception rule.",
    {
      rule_id: z.string().describe("Rule ID to enable"),
    },
    async ({ rule_id }) => {
      try {
        await proxyManager.enableRule(rule_id);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: `Rule '${rule_id}' enabled.` }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_disable_rule",
    "Disable an interception rule without removing it.",
    {
      rule_id: z.string().describe("Rule ID to disable"),
    },
    async ({ rule_id }) => {
      try {
        await proxyManager.disableRule(rule_id);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", message: `Rule '${rule_id}' disabled.` }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );
}
