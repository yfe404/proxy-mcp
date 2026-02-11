export type DevToolsAction =
  | "navigate"
  | "snapshot"
  | "listNetwork"
  | "listConsole"
  | "screenshot";

export interface DevToolsResolvedToolMap {
  navigate: string;
  snapshot: string;
  listNetwork: string;
  listConsole: string;
  screenshot: string;
}

export interface DevToolsSessionSnapshot {
  id: string;
  targetId: string;
  browserUrl: string;
  mode: "sidecar" | "native-fallback";
  createdAt: number;
  lastUsedAt: number;
  sidecarPid: number | null;
  tools: DevToolsResolvedToolMap | null;
}
