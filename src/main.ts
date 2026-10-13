/**
 * GPN Server — HTTP API with user accounts.
 *
 * Auth:
 *   POST /api/auth/register  {username, password} -> {user, accessToken, refreshToken}
 *   POST /api/auth/login     {username, password} -> {user, accessToken, refreshToken}
 *   POST /api/auth/refresh   {refreshToken}       -> {accessToken, refreshToken}
 *   POST /api/auth/logout    {refreshToken}
 *   GET  /api/auth/me        (Bearer)             -> {user}
 *   Access token: HMAC-signed, 24h, also cached in Redis gpn:auth:token:<t>
 *   Refresh token: 30d in Redis gpn:auth:refresh:<r>
 *   Users stored in Postgres (gpn db, users table), scrypt password hashes.
 *   First registered user becomes admin. Shared machine token (apiToken)
 *   still works as an admin override for headless/tunnel flows.
 *
 * Game routing (Bearer: user token or machine token):
 *   POST /api/register — WG peer registration
 *   POST /api/targets  — dynamic allowed-ips for the peer
 *   GET  /api/state    — debug
 */
import { readFileSync } from "node:fs";
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { loadConfig, type Config } from "./config.ts";
import { WgManager, type Peer } from "./wireguard.ts";
import { Pool } from "pg";
import Redis from "ioredis";

const cfg: Config = loadConfig();
if (!cfg.apiToken) {
  console.error("[gpn-server] FATAL: apiToken not set in server.config.json");
  process.exit(1);
}

const pg = new Pool({
  host: cfg.db?.host ?? "127.0.0.1",
  port: cfg.db?.port ?? 5432,
  database: cfg.db?.name ?? "gpn",
  user: cfg.db?.user ?? "gpn",
  password: cfg.db?.password ?? "gpn_local_9f3k",
});
const redis = new Redis({ host: cfg.redis?.host ?? "127.0.0.1", port: cfg.redis?.port ?? 6379 });

const wg = new WgManager(cfg.wgInterface, cfg.wgSubnet);
const peers = new Map<string, Peer>(); // publicKey -> Peer
const usedIps = new Set<string>();

// ============ db init ============
async function initDb() {
  await pg.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT now(),
      last_login TIMESTAMPTZ
    )`);
  const { rows } = await pg.query("SELECT count(*)::int AS n FROM users");
  if (rows[0].n === 0) {
    const pw = randomBytes(12).toString("hex");
    await createUser("admin", pw, "admin");
    console.log(`\n[gpn-server] ====================================`);
    console.log(`[gpn-server] FIRST USER CREATED (admin)`);
    console.log(`[gpn-server]   username: admin`);
    console.log(`[gpn-server]   password: ${pw}`);
    console.log(`[gpn-server] CHANGE THIS AFTER FIRST LOGIN`);
    console.log(`[gpn-server] ====================================\n`);
  }
}

// ============ passwords (scrypt) ============
function hashPassword(pw: string): string {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${scryptSync(pw, salt, 64).toString("hex")}`;
}
function verifyPassword(pw: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  return timingSafeEqual(scryptSync(pw, salt, 64), Buffer.from(hash, "hex"));
}

async function createUser(username: string, password: string, role = "user") {
  const { rows } = await pg.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id, username, role, created_at",
    [username.toLowerCase(), hashPassword(password), role]
  );
  const u = rows[0];
  await redis.set(`gpn:user:${u.id}`, JSON.stringify(u));
  await redis.set(`gpn:user:name:${u.username}`, String(u.id));
  return u;
}

// ============ tokens ============
const JWT_SECRET = cfg.apiToken;

function signToken(userId: number, ttlMs: number): string {
  const payload = { uid: userId, exp: Date.now() + ttlMs, nonce: randomBytes(8).toString("hex") };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}
function verifyToken(token: string): { uid: number } | null {
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  if (sig.length !== expected.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (Date.now() > payload.exp) return null;
    return { uid: payload.uid };
  } catch {
    return null;
  }
}

async function issueTokens(userId: number) {
  const accessToken = signToken(userId, 24 * 3600_000);
  const refreshToken = randomBytes(32).toString("hex");
  await redis.set(`gpn:auth:token:${accessToken}`, String(userId), "EX", 24 * 3600);
  await redis.set(`gpn:auth:refresh:${refreshToken}`, String(userId), "EX", 30 * 24 * 3600);
  return { accessToken, refreshToken };
}

/** Bearer token -> user info, or null. Accepts user tokens + shared machine token. */
async function authUser(req: Request): Promise<{ uid: number | null; role: string } | null> {
  const h = req.headers.get("authorization") ?? "";
  if (!h.startsWith("Bearer ")) return null;
  const token = h.slice(7);
  if (token === cfg.apiToken) return { uid: null, role: "admin" };
  const cached = await redis.get(`gpn:auth:token:${token}`);
  if (cached) return { uid: parseInt(cached, 10), role: "user" };
  const v = verifyToken(token);
  if (!v) return null;
  await redis.set(`gpn:auth:token:${token}`, String(v.uid), "EX", 24 * 3600);
  return { uid: v.uid, role: "user" };
}

// ============ peers ============
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

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface TargetBody {
  targets?: { ip?: string; port?: number; proto?: string }[];
}

function isValidIp(ip: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split(".").every((o) => +o <= 255);
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);

  if (url.pathname === "/api/health") return json({ ok: true, ts: Date.now() });

  // ---------- auth endpoints (public) ----------
  if (url.pathname === "/api/auth/register" && req.method === "POST") {
    const { username, password } = await req.json();
    if (typeof username !== "string" || !/^[a-zA-Z0-9_-]{3,24}$/.test(username))
      return json({ error: "username must be 3-24 chars [a-zA-Z0-9_-]" }, 400);
    if (typeof password !== "string" || password.length < 8)
      return json({ error: "password must be 8+ chars" }, 400);
    if (await redis.get(`gpn:user:name:${username.toLowerCase()}`))
      return json({ error: "username taken" }, 409);
    const { rows } = await pg.query("SELECT count(*)::int AS n FROM users");
    const role = rows[0].n === 0 ? "admin" : "user";
    const u = await createUser(username, password, role);
    const tokens = await issueTokens(u.id);
    console.log(`[gpn-server] user registered: ${u.username} (${u.role})`);
    return json({ ok: true, user: { id: u.id, username: u.username, role: u.role }, ...tokens });
  }

  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    const { username, password } = await req.json();
    const { rows } = await pg.query("SELECT id, password_hash, role FROM users WHERE username = $1", [
      (username ?? "").toLowerCase(),
    ]);
    if (!rows.length || !verifyPassword(password ?? "", rows[0].password_hash))
      return json({ error: "invalid credentials" }, 401);
    await pg.query("UPDATE users SET last_login = now() WHERE id = $1", [rows[0].id]);
    const tokens = await issueTokens(rows[0].id);
    return json({
      ok: true,
      user: { id: rows[0].id, username: (username ?? "").toLowerCase(), role: rows[0].role },
      ...tokens,
    });
  }

  if (url.pathname === "/api/auth/refresh" && req.method === "POST") {
    const { refreshToken } = await req.json();
    const uid = await redis.get(`gpn:auth:refresh:${refreshToken ?? ""}`);
    if (!uid) return json({ error: "invalid refresh token" }, 401);
    await redis.del(`gpn:auth:refresh:${refreshToken}`);
    const tokens = await issueTokens(parseInt(uid, 10));
    return json({ ok: true, ...tokens });
  }

  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    const { refreshToken } = await req.json();
    if (refreshToken) await redis.del(`gpn:auth:refresh:${refreshToken}`);
    return json({ ok: true });
  }

  // ---------- everything below requires a token ----------
  const auth = await authUser(req);
  if (!auth) return json({ error: "unauthorized" }, 401);

  if (url.pathname === "/api/auth/me") {
    if (auth.uid === null) return json({ user: { username: "machine", role: "admin" } });
    const { rows } = await pg.query("SELECT id, username, role, created_at, last_login FROM users WHERE id = $1", [auth.uid]);
    return json({ user: rows[0] ?? null });
  }

  if (url.pathname === "/api/register" && req.method === "POST") {
    const { publicKey, name } = await req.json();
    if (typeof publicKey !== "string" || publicKey.length < 40) {
      return json({ error: "publicKey required (wireguard pub key)" }, 400);
    }
    let peer = peers.get(publicKey);
    if (!peer) {
      const ip = await wg.allocateIp(usedIps);
      peer = {
        publicKey,
        ip,
        name: name ?? (auth.uid ? `user-${auth.uid}` : "client"),
        allowedGameTargets: [],
        lastSeen: Date.now(),
        createdAt: Date.now(),
      };
      peers.set(publicKey, peer);
      usedIps.add(ip);
      await wg.addPeer(publicKey, ip);
      console.log(`[gpn-server] registered peer ${peer.name} -> ${ip}`);
    }
    const serverPub = readFileSync("/etc/wireguard/server.pub", "utf8").trim();
    const endpoint = `${cfg.publicEndpoint ?? "43.134.108.20"}:51820`;
    return json({ ok: true, ip: peer.ip, serverPublicKey: serverPub, endpoint, subnet: cfg.wgSubnet });
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
      auth: auth.uid ? `user:${auth.uid}` : "machine",
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

await initDb();
await restorePeers();
Bun.serve({
  port: cfg.port,
  fetch: (req) => handle(req).catch((e) => json({ error: String(e) }, 500)),
});
console.log(`[gpn-server] listening on :${cfg.port} (wg ${cfg.wgInterface}, ${cfg.wgSubnet}, auth pg+redis)`);
