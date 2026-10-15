import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface Config {
  /** Shared machine token (admin override for headless/tunnel flows) */
  apiToken: string;
  /** HTTP listen port (Caddy proxies gpn.fuckitweball.online here) */
  port: number;
  /** WireGuard interface */
  wgInterface: string;
  /** WireGuard UDP listen port advertised to clients */
  wgPort: number;
  /** Public endpoint clients should connect to (ip or hostname) — required */
  publicEndpoint?: string;
  /** WG subnet clients are drawn from */
  wgSubnet: string;
  /** Max game targets a single peer may hold */
  maxTargets: number;
  /** Max WG peers a non-admin user may register */
  maxPeersPerUser: number;
  /** If set, POST /api/auth/register requires this invite code */
  inviteCode?: string;
  /** Postgres (user accounts). Password may also come from GPN_DB_PASSWORD. */
  db?: { host?: string; port?: number; name?: string; user?: string; password?: string };
  /** Redis (auth token store) */
  redis?: { host?: string; port?: number };
}

export const DEFAULT_CONFIG: Config = {
  apiToken: "",
  port: 9090,
  wgInterface: "wg0",
  wgPort: 51820,
  wgSubnet: "10.66.0.0/24",
  maxTargets: 64,
  maxPeersPerUser: 5,
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
