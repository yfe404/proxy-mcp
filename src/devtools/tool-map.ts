import type { DevToolsAction, DevToolsResolvedToolMap } from "./types.js";

const CANDIDATES: Record<DevToolsAction, string[]> = {
  navigate: ["navigate_page", "browser_navigate"],
  snapshot: ["take_snapshot", "browser_snapshot"],
  listNetwork: ["list_network_requests", "browser_network_requests"],
  listConsole: ["list_console_messages", "browser_console_messages"],
  screenshot: ["take_screenshot", "browser_take_screenshot"],
};

function pickCandidate(candidates: string[], available: Set<string>): string | null {
  for (const candidate of candidates) {
    if (available.has(candidate)) return candidate;
  }
  return null;
}

export function resolveToolMap(availableTools: string[]): DevToolsResolvedToolMap {
  const available = new Set(availableTools);

  const resolved = {
    navigate: pickCandidate(CANDIDATES.navigate, available),
    snapshot: pickCandidate(CANDIDATES.snapshot, available),
    listNetwork: pickCandidate(CANDIDATES.listNetwork, available),
    listConsole: pickCandidate(CANDIDATES.listConsole, available),
    screenshot: pickCandidate(CANDIDATES.screenshot, available),
  };

  const missing: string[] = [];
  if (!resolved.navigate) missing.push("navigate");
  if (!resolved.snapshot) missing.push("snapshot");
  if (!resolved.listNetwork) missing.push("listNetwork");
  if (!resolved.listConsole) missing.push("listConsole");
  if (!resolved.screenshot) missing.push("screenshot");

  if (missing.length > 0) {
    const preview = availableTools.slice(0, 30).join(", ");
    throw new Error(
      `chrome-devtools-mcp is missing required tools: ${missing.join(", ")}. ` +
      `Available tools (first 30): ${preview || "(none)"}`,
    );
  }

  return {
    navigate: resolved.navigate!,
    snapshot: resolved.snapshot!,
    listNetwork: resolved.listNetwork!,
    listConsole: resolved.listConsole!,
    screenshot: resolved.screenshot!,
  };
}
