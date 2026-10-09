/**
 * GPN Server — HTTP API for clients.
 *
 * Endpoints (all under Bearer auth except /api/health):
 *   GET  /api/health          — liveness
 *   POST /api/register        — {publicKey, name} -> {ip, serverPubKey, endpoint, subnet}
 *   POST /api/targets         — {targets:[{ip,port,proto}]} -> routes game IPs for this client's peer
 *   GET  /api/state           — debugging: current peers + targets
 *
 * The client's WireGuard peer uses allowed-ips = [peer_ip/32, ...game target IPs],
 * so only game traffic routed into the tunnel gets forwarded; everything else
 * stays on the physical connection.
 */
import { readFileSync } from "node:fs";
import { loadConfig, type Config } from "./config.ts";
import { WgManager, type Peer } from "./wireguard.ts";

const cfg: Config = loadConfig();

if (!cfg.apiToken) {
  console.error("[gpn-server] FATAL: apiToken not set in server.config.json");
  process.exit(1);
}

const wg = new WgManager(cfg.wgInterface, cfg.wgSubnet);
const peers = new Map<string, Peer>(); // publicKey -> Peer
const usedIps = new Set<string>();

// Restore peers that already exist in WireGuard (e.g. after server restart)
async function restorePeers() {
  const existing = await wg.listPeers();
  for (const [pub, info] of existing) {
    if (!info.ip) continue;
    peers.set(pub, {
      publicKey: pub,
      ip: info.ip,
      name: "(restored)",
      allowedGameTargets: [],
      lastSeen: Date.now(),
      createdAt: Date.now(),
    });
    usedIps.add(info.ip);
  }
  if (existing.size) console.log(`[gpn-server] restored ${existing.size} existing peer(s)`);
}

function auth(req: Request): boolean {
  const h = req.headers.get("authorization") ?? "";
  return h === `Bearer ${cfg.apiToken}`;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface TargetBody {
  targets?: { ip?: string; port?: number; proto?: string }[];
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);

  if (url.pathname === "/api/health") {
    return json({ ok: true, ts: Date.now() });
  }

  if (!auth(req)) return json({ error: "unauthorized" }, 401);

  if (url.pathname === "/api/register" && req.method === "POST") {
    const { publicKey, name } = await req.json();
    if (typeof publicKey !== "string" || publicKey.length < 40) {
      return json({ error: "publicKey required (wireguard pub key)" }, 400);
    }
    let peer = peers.get(publicKey);
    if (!peer) {
      const ip = await wg.allocateIp(usedIps);
      peer = { publicKey, ip, name: name ?? "client", allowedGameTargets: [], lastSeen: Date.now(), createdAt: Date.now() };
      peers.set(publicKey, peer);
      usedIps.add(ip);
      await wg.addPeer(publicKey, ip);
      console.log(`[gpn-server] registered peer ${name ?? "?"} -> ${ip}`);
    }
    const serverPub = readFileSync("/etc/wireguard/server.pub", "utf8").trim();
    // Use a public IP for the WG endpoint — never the Host header (may be a
    // domain without DNS, or localhost behind Caddy). Configurable via config.
    const endpoint = `${cfg.publicEndpoint ?? "43.134.108.20"}:51820`;
    return json({
      ok: true,
      ip: peer.ip,
      serverPublicKey: serverPub,
      endpoint,
      subnet: cfg.wgSubnet,
    });
  }

  if (url.pathname === "/api/targets" && req.method === "POST") {
    const body: TargetBody = await req.json();
    const clientPub = req.headers.get("x-gpn-peer");
    if (!clientPub) return json({ error: "x-gpn-peer header required (your wireguard public key)" }, 400);
    const peer = peers.get(clientPub);
    if (!peer) return json({ error: "unknown peer — register first" }, 404);

    const targets = (body.targets ?? [])
      .map((t) => (t.ip ?? "").trim())
      .filter((ip) => isValidIp(ip) && ip !== "127.0.0.1" && !ip.startsWith("10.66.") && !ip.startsWith("192.168.") && !ip.startsWith("172."));
    const unique = [...new Set(targets)];

    const prev = new Set(peer.allowedGameTargets);
    const next = new Set(unique);
    const added = [...next].filter((x) => !prev.has(x));
    const removed = [...prev].filter((x) => !next.has(x));

    for (const ip of added) await wg.addTargetForPeer(clientPub, ip);
    for (const ip of removed) await wg.removeTargetForPeer(clientPub, ip);
    peer.allowedGameTargets = unique;
    peer.lastSeen = Date.now();

    return json({ ok: true, routed: unique, added, removed });
  }

  if (url.pathname === "/api/state") {
    return json({
      peers: [...peers.values()].map((p) => ({
        name: p.name,
        ip: p.ip,
        targets: p.allowedGameTargets,
        lastSeenAgoMs: Date.now() - p.lastSeen,
      })),
    });
  }

  return json({ error: "not found" }, 404);
}

function isValidIp(ip: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split(".").every((o) => +o <= 255);
}

// periodic cleanup of stale peers (no handshake in 1h)
setInterval(() => {
  const now = Date.now();
  for (const [pub, peer] of peers) {
    if (now - peer.lastSeen > 3_600_000) {
      peers.delete(pub);
      usedIps.delete(peer.ip);
      wg.removePeer(pub).catch((e) => console.error("[gpn-server] peer cleanup failed:", e));
      console.log(`[gpn-server] removed stale peer ${peer.name} (${peer.ip})`);
    }
  }
}, 600_000);

await restorePeers();
Bun.serve({
  port: cfg.port,
  fetch: (req) => handle(req).catch((e) => json({ error: String(e) }, 500)),
});
console.log(`[gpn-server] listening on :${cfg.port} (wg ${cfg.wgInterface}, ${cfg.wgSubnet})`);
