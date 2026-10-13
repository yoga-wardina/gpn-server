import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface Config {
  /** Bearer token clients must present */
  apiToken: string;
  /** HTTP listen port (Caddy proxies gpn.fuckitweball.online here) */
  port: number;
  /** WireGuard interface */
  wgInterface: string;
  /** Public endpoint clients should connect to (ip or hostname) */
  publicEndpoint?: string;
  /** WireGuard server private key file */
  wgPrivateKeyFile: string;
  /** WG subnet clients are drawn from */
  wgSubnet: string;
  /** Game IPs are routed through wg; everything else goes direct.
   *  "client" mode: per-client dynamic peers. "route" mode: add nftables routes. */
  mode: "client" | "route";
  /** Target expiry: drop client IPs not refreshed within this many ms */
  targetTtlMs: number;
  /** Postgres (user accounts) */
  db?: { host?: string; port?: number; name?: string; user?: string; password?: string };
  /** Redis (auth token cache) */
  redis?: { host?: string; port?: number };
}

export const DEFAULT_CONFIG: Config = {
  apiToken: "",
  port: 9090,
  wgInterface: "wg0",
  wgPrivateKeyFile: "/etc/wireguard/server.key",
  wgSubnet: "10.66.0.0/24",
  mode: "client",
  targetTtlMs: 15_000,
};

const CONFIG_PATH = join(import.meta.dir, "..", "server.config.json");

export function loadConfig(): Config {
  if (existsSync(CONFIG_PATH)) {
    try {
      const loaded = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
      return { ...DEFAULT_CONFIG, ...loaded };
    } catch (e) {
      console.error("[gpn-server] config parse failed, using defaults:", e);
      return { ...DEFAULT_CONFIG };
    }
  }
  writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
  console.log(`[gpn-server] wrote default config to ${CONFIG_PATH} — set apiToken before use`);
  return { ...DEFAULT_CONFIG };
}

export function saveConfig(cfg: Config) {
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}
