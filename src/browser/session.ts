/**
 * Shared helpers for resolving a Playwright Page from a browser interceptor target ID.
 * Used by humanizer and browser tools so they don't each re-walk the interceptor map.
 */

import type { Page } from "playwright-core";
import { interceptorManager } from "../interceptors/manager.js";
import type { BrowserInterceptor, BrowserTargetEntry } from "../interceptors/browser.js";

function getBrowserInterceptor(): BrowserInterceptor {
  const it = interceptorManager.get("browser") as BrowserInterceptor | undefined;
  if (!it) throw new Error("Browser interceptor not registered.");
  return it;
}

export function getEntry(targetId: string): BrowserTargetEntry {
  const entry = getBrowserInterceptor().getEntry(targetId);
  if (!entry) throw new Error(`Browser target '${targetId}' not found. Is it still running?`);
  return entry;
}

export function getPageForTarget(targetId: string): Page {
  const entry = getEntry(targetId);
  if (entry.page.isClosed()) {
    throw new Error(`Page for browser target '${targetId}' is closed.`);
  }
  return entry.page;
}
