/**
 * Modification shortcut tools — convenience wrappers for common rule patterns.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { proxyManager } from "../state.js";
import type { RuleMatcher, RuleHandler } from "../state.js";

export function registerModificationTools(server: McpServer): void {
  server.tool(
    "proxy_inject_headers",
    "Add or overwrite headers on matching traffic. Creates a passthrough rule with header transforms.",
    {
      hostname: z.string().optional().describe("Hostname to match (optional)"),
      url_pattern: z.string().optional().describe("URL regex pattern to match (optional)"),
      headers: z.record(z.string().nullable()).describe("Headers to inject (key-value pairs, set value to null to delete a header)"),
      direction: z.enum(["request", "response", "both"]).optional().default("request")
        .describe("Where to inject: request, response, or both"),
      priority: z.number().optional().default(50).describe("Rule priority (default: 50)"),
    },
    async ({ hostname, url_pattern, headers, direction, priority }) => {
      try {
        const matcher: RuleMatcher = {};
        if (hostname) matcher.hostname = hostname;
        if (url_pattern) matcher.urlPattern = url_pattern;

        const handler: RuleHandler = { type: "passthrough" };
        if (direction === "request" || direction === "both") {
          handler.transformRequest = { updateHeaders: headers };
        }
        if (direction === "response" || direction === "both") {
          handler.transformResponse = { updateHeaders: headers };
        }

        const rule = await proxyManager.addRule({
          priority,
          enabled: true,
          description: `Inject headers: ${Object.keys(headers).join(", ")} (${direction})`,
          matcher,
          handler,
        });

        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", rule_id: rule.id, description: rule.description }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_rewrite_url",
    "Rewrite request URLs matching a pattern. Creates a passthrough rule with body match-replace on the URL.",
    {
      match_pattern: z.string().describe("Regex pattern to match in URLs"),
      replace_with: z.string().describe("Replacement string"),
      hostname: z.string().optional().describe("Limit to this hostname"),
      priority: z.number().optional().default(50).describe("Rule priority (default: 50)"),
    },
    async ({ match_pattern, replace_with, hostname, priority }) => {
      try {
        const matcher: RuleMatcher = {};
        if (hostname) matcher.hostname = hostname;
        matcher.urlPattern = match_pattern;

        const handler: RuleHandler = {
          type: "passthrough",
          transformRequest: {
            matchReplaceBody: [[match_pattern, replace_with]],
          },
        };

        const rule = await proxyManager.addRule({
          priority,
          enabled: true,
          description: `URL rewrite: ${match_pattern} → ${replace_with}`,
          matcher,
          handler,
        });

        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", rule_id: rule.id, description: rule.description }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "proxy_mock_response",
    "Return a mock response for matched requests. Creates a mock rule.",
    {
      method: z.string().optional().describe("HTTP method to match (optional)"),
      url_pattern: z.string().optional().describe("URL regex pattern to match (optional)"),
      hostname: z.string().optional().describe("Hostname to match (optional)"),
      status: z.number().describe("Response status code"),
      body: z.string().optional().default("").describe("Response body"),
      content_type: z.string().optional().default("application/json").describe("Content-Type header"),
      priority: z.number().optional().default(10).describe("Rule priority (default: 10, high priority)"),
    },
    async ({ method, url_pattern, hostname, status, body, content_type, priority }) => {
      try {
        const matcher: RuleMatcher = {};
        if (method) matcher.method = method;
        if (url_pattern) matcher.urlPattern = url_pattern;
        if (hostname) matcher.hostname = hostname;

        const handler: RuleHandler = {
          type: "mock",
          status,
          body: body ?? "",
          headers: { "content-type": content_type ?? "application/json" },
        };

        const rule = await proxyManager.addRule({
          priority,
          enabled: true,
          description: `Mock ${status} for ${method || "ANY"} ${url_pattern || hostname || "*"}`,
          matcher,
          handler,
        });

        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "success", rule_id: rule.id, description: rule.description }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );
}
