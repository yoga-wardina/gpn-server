/**
 * GPN Server — HTTP API with user accounts.
 *
 * Auth:
 *   POST /api/auth/register  {username, password[, inviteCode]} -> {user, accessToken, refreshToken}
 *   POST /api/auth/login     {username, password} -> {user, accessToken, refreshToken}
 *   POST /api/auth/refresh   {refreshToken}       -> {accessToken, refreshToken}
 *   POST /api/auth/logout    {refreshToken}
 *   POST /api/auth/password  {oldPassword, newPassword} (Bearer) -> new tokens, all others revoked
 *   GET  /api/auth/me        (Bearer)             -> {user}
 *   Tokens are opaque random strings stored in Redis (access 24h, refresh 30d),
 *   with a per-user index so they can be revoked. Role/status are read from
 *   Postgres on every request. Users: Postgres, scrypt password hashes.
 *   The shared machine token (apiToken) still works as an admin override.
 *
 * Game routing (Bearer: user token or machine token):
 *   POST /api/register — WG peer registration (peer is owned by the caller)
 *   POST /api/targets  — dynamic allowed-ips for the caller's peer
 *   GET  /api/state    — own peers (all peers for admins)
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { loadConfig, type Config } from "./config.ts";
import { WgManager, type Peer } from "./wireguard.ts";
import { ProbeManager } from "./probe.ts";
import { startDupRelay } from "./udpdup.ts";
import { Pool } from "pg";
import Redis from "ioredis";

const cfg: Config = loadConfig();
const dbPassword = cfg.db?.password ?? process.env.GPN_DB_PASSWORD;
if (!cfg.apiToken) fatal("apiToken not set in server.config.json");
if (!dbPassword) fatal("db.password (or GPN_DB_PASSWORD env) not set");
if (!cfg.publicEndpoint) fatal("publicEndpoint not set in server.config.json");

function fatal(msg: string): never {
  console.error(`[gpn-server] FATAL: ${msg}`);
  process.exit(1);
}

const pg = new Pool({
  host: cfg.db?.host ?? "127.0.0.1",
  port: cfg.db?.port ?? 5432,
  database: cfg.db?.name ?? "gpn",
  user: cfg.db?.user ?? "gpn",
  password: dbPassword,
});
pg.on("error", (e: Error) => console.error("[gpn-server] pg idle client error:", e.message));
const redis = new Redis({ host: cfg.redis?.host ?? "127.0.0.1", port: cfg.redis?.port ?? 6379 });
redis.on("error", (e: Error) => console.error("[gpn-server] redis error:", e.message));

const wg = new WgManager(cfg.wgInterface, cfg.wgSubnet);
const peers = new Map<string, Peer>(); // publicKey -> Peer
const dupEndpoint = () => (cfg.dupPort > 0 ? `${cfg.publicEndpoint}:${cfg.dupPort}` : null);
const probes = new ProbeManager(); // latency/loss from this server to clients' game servers
const usedIps = new Set<string>();

class HttpError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

// ============ db init ============
async function initDb() {
  await pg.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT now(),
      last_login TIMESTAMPTZ
    )`);
  await pg.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'`);
  const { rows } = await pg.query("SELECT count(*)::int AS n FROM users");
  if (rows[0].n === 0) {
    const pw = randomBytes(12).toString("hex");
    await createUser("admin", pw, "admin");
    // Written to a 0600 file rather than stdout so it doesn't end up in the journal.
    const file = join(import.meta.dir, "..", "admin-initial-password.txt");
    writeFileSync(file, `username: admin\npassword: ${pw}\n`, { mode: 0o600 });
    console.log(`[gpn-server] first user 'admin' created; initial password written to ${file}`);
    console.log(`[gpn-server] log in, change it via POST /api/auth/password, then delete that file`);
  }
}

// ============ passwords (async scrypt) ============
function scryptAsync(pw: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(pw, salt, 64, (err, key) => (err ? reject(err) : resolve(key))));
}
async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  return `${salt}:${(await scryptAsync(pw, salt)).toString("hex")}`;
}
async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, "hex");
  const actual = await scryptAsync(pw, salt);
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}
// Verified against when the username doesn't exist, so response time doesn't reveal valid usernames.
let DUMMY_HASH = "";

async function createUser(username: string, password: string, role = "user") {
  try {
    const { rows } = await pg.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id, username, role, created_at",
      [username.toLowerCase(), await hashPassword(password), role]
    );
    return rows[0];
  } catch (e: any) {
    if (e?.code === "23505") throw new HttpError(409, "username taken");
    throw e;
  }
}

// ============ tokens (opaque, Redis-backed, revocable) ============
type TokenKind = "token" | "refresh";
const TTL_SEC: Record<TokenKind, number> = { token: 24 * 3600, refresh: 30 * 24 * 3600 };
const tokenKey = (kind: TokenKind, t: string) => `gpn:auth:${kind}:${t}`;
const indexKey = (kind: TokenKind, uid: number) => `gpn:auth:idx:${kind}:${uid}`;

async function mintToken(kind: TokenKind, uid: number): Promise<string> {
  const t = randomBytes(32).toString("hex");
  const now = Date.now();
  const idx = indexKey(kind, uid);
  await redis
    .multi()
    .set(tokenKey(kind, t), String(uid), "EX", TTL_SEC[kind])
    .zremrangebyscore(idx, 0, now) // prune expired entries
    .zadd(idx, now + TTL_SEC[kind] * 1000, t)
    .expire(idx, TTL_SEC[kind])
    .exec();
  return t;
}

async function issueTokens(uid: number) {
  return { accessToken: await mintToken("token", uid), refreshToken: await mintToken("refresh", uid) };
}

async function revokeToken(kind: TokenKind, t: string) {
  const uid = await redis.get(tokenKey(kind, t));
  const m = redis.multi().del(tokenKey(kind, t));
  if (uid) m.zrem(indexKey(kind, parseInt(uid, 10)), t);
  await m.exec();
}

async function revokeAllTokens(uid: number) {
  for (const kind of ["token", "refresh"] as const) {
    const idx = indexKey(kind, uid);
    const members = await redis.zrange(idx, "0", "-1");
    const m = redis.multi();
    for (const t of members) m.del(tokenKey(kind, t));
    m.del(idx);
    await m.exec();
  }
}

interface Auth {
  uid: number | null; // null = machine token
  role: string;
}

/** Bearer token -> Auth, or null if invalid. Throws 403 for inactive accounts. */
async function authUser(req: Request): Promise<Auth | null> {
  const h = req.headers.get("authorization") ?? "";
  if (!h.startsWith("Bearer ")) return null;
  const token = h.slice(7);
  if (safeEqual(token, cfg.apiToken)) return { uid: null, role: "admin" };
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const cached = await redis.get(tokenKey("token", token));
  if (!cached) return null;
  const uid = parseInt(cached, 10);
  const { rows } = await pg.query("SELECT role, status FROM users WHERE id = $1", [uid]);
  if (!rows.length) return null;
  if (rows[0].status !== "active") throw new HttpError(403, "account is inactive — contact an admin");
  return { uid, role: rows[0].role };
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

// ============ rate limiting (in-memory, per client IP) ============
const hits = new Map<string, { n: number; reset: number }>();
function rateLimit(key: string, max: number, windowMs: number) {
  const now = Date.now();
  const e = hits.get(key);
  if (!e || now > e.reset) {
    hits.set(key, { n: 1, reset: now + windowMs });
    return;
  }
  if (++e.n > max) throw new HttpError(429, "too many requests — slow down");
}
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
}, 60_000).unref();

function clientIp(req: Request, server: { requestIP(r: Request): { address: string } | null }): string {
  // Caddy sets X-Forwarded-For; fall back to the socket peer.
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || server.requestIP(req)?.address || "unknown";
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
      owner: null, // claimed by the first authenticated user who registers this key
      allowedGameTargets: info.targets,
      lastSeen: Date.now(), // grace period after a restart
      createdAt: Date.now(),
    });
    usedIps.add(info.ip);
  }
  if (existing.size) console.log(`[gpn-server] restored ${existing.size} existing peer(s)`);
}

function canAccess(auth: Auth, peer: Peer): boolean {
  return auth.role === "admin" || (auth.uid !== null && peer.owner === auth.uid);
}

let serverPub: string | null = null;
function serverPublicKey(): string {
  return (serverPub ??= readFileSync("/etc/wireguard/server.pub", "utf8").trim());
}

const WG_KEY = /^[A-Za-z0-9+/]{43}=$/;

// ============ target validation ============
function parseIpv4(ip: string): number[] | null {
  const m = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

/** Public, globally-routable unicast IPv4 only. */
function isPublicIpv4(ip: string): boolean {
  const o = parseIpv4(ip);
  if (!o) return false;
  const [a, b, c] = o as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return false;
  if (a >= 224) return false; // multicast + reserved + broadcast
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 169 && b === 254) return false; // link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

// ============ http helpers ============
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function readJson(req: Request): Promise<Record<string, any>> {
  try {
    const body = await req.json();
    if (body && typeof body === "object" && !Array.isArray(body)) return body;
  } catch {}
  throw new HttpError(400, "invalid JSON body");
}

const str = (v: unknown) => (typeof v === "string" ? v : "");

async function handle(req: Request, ip: string): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (path === "/api/health") return json({ ok: true, ts: Date.now(), dup: dupEndpoint() });

  // ---------- auth endpoints (public, rate limited) ----------
  if (path === "/api/auth/register" && req.method === "POST") {
    rateLimit(`register:${ip}`, 5, 3600_000);
    const body = await readJson(req);
    const username = str(body.username);
    const password = str(body.password);
    if (cfg.inviteCode && !safeEqual(str(body.inviteCode), cfg.inviteCode))
      return json({ error: "invalid invite code" }, 403);
    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username))
      return json({ error: "username must be 3-24 chars [a-zA-Z0-9_-]" }, 400);
    if (password.length < 8 || password.length > 128) return json({ error: "password must be 8-128 chars" }, 400);
    const u = await createUser(username, password, "user");
    const tokens = await issueTokens(u.id);
    console.log(`[gpn-server] user registered: ${u.username}`);
    return json({ ok: true, user: { id: u.id, username: u.username, role: u.role }, ...tokens });
  }

  if (path === "/api/auth/login" && req.method === "POST") {
    rateLimit(`login:${ip}`, 10, 60_000);
    const body = await readJson(req);
    const username = str(body.username).toLowerCase();
    const { rows } = await pg.query("SELECT id, password_hash, role, status FROM users WHERE username = $1", [username]);
    const ok = await verifyPassword(str(body.password), rows[0]?.password_hash ?? DUMMY_HASH);
    if (!rows.length || !ok) return json({ error: "invalid credentials" }, 401);
    if (rows[0].status !== "active") return json({ error: "account is inactive — contact an admin" }, 403);
    await pg.query("UPDATE users SET last_login = now() WHERE id = $1", [rows[0].id]);
    const tokens = await issueTokens(rows[0].id);
    return json({
      ok: true,
      user: { id: rows[0].id, username, role: rows[0].role, status: rows[0].status },
      ...tokens,
    });
  }

  if (path === "/api/auth/refresh" && req.method === "POST") {
    rateLimit(`refresh:${ip}`, 30, 60_000);
    const refreshToken = str((await readJson(req)).refreshToken);
    const uidStr = refreshToken ? await redis.get(tokenKey("refresh", refreshToken)) : null;
    if (!uidStr) return json({ error: "invalid refresh token" }, 401);
    const uid = parseInt(uidStr, 10);
    await revokeToken("refresh", refreshToken);
    const { rows } = await pg.query("SELECT status FROM users WHERE id = $1", [uid]);
    if (!rows.length || rows[0].status !== "active") return json({ error: "account is inactive — contact an admin" }, 403);
    return json({ ok: true, ...(await issueTokens(uid)) });
  }

  if (path === "/api/auth/logout" && req.method === "POST") {
    const refreshToken = str((await readJson(req)).refreshToken);
    if (refreshToken) await revokeToken("refresh", refreshToken);
    const bearer = (req.headers.get("authorization") ?? "").slice(7);
    if (/^[0-9a-f]{64}$/.test(bearer)) await revokeToken("token", bearer);
    return json({ ok: true });
  }

  // ---------- everything below requires a token ----------
  const auth = await authUser(req);
  if (!auth) return json({ error: "unauthorized" }, 401);

  if (path === "/api/auth/me") {
    if (auth.uid === null) return json({ user: { username: "machine", role: "admin" } });
    const { rows } = await pg.query("SELECT id, username, role, status, created_at, last_login FROM users WHERE id = $1", [auth.uid]);
    return json({ user: rows[0] });
  }

  if (path === "/api/auth/password" && req.method === "POST") {
    if (auth.uid === null) return json({ error: "machine token has no password" }, 400);
    rateLimit(`password:${ip}`, 10, 60_000);
    const body = await readJson(req);
    const newPassword = str(body.newPassword);
    if (newPassword.length < 8 || newPassword.length > 128) return json({ error: "password must be 8-128 chars" }, 400);
    const { rows } = await pg.query("SELECT password_hash FROM users WHERE id = $1", [auth.uid]);
    if (!rows.length || !(await verifyPassword(str(body.oldPassword), rows[0].password_hash)))
      return json({ error: "invalid credentials" }, 401);
    await pg.query("UPDATE users SET password_hash = $1 WHERE id = $2", [await hashPassword(newPassword), auth.uid]);
    await revokeAllTokens(auth.uid);
    return json({ ok: true, ...(await issueTokens(auth.uid)) });
  }

  // ---------- admin: user management ----------
  if (path.startsWith("/api/admin/") && auth.role !== "admin") {
    return json({ error: "admin only" }, 403);
  }

  if (path === "/api/admin/users" && req.method === "GET") {
    const { rows } = await pg.query("SELECT id, username, role, status, created_at, last_login FROM users ORDER BY id");
    return json({ users: rows });
  }

  // POST /api/admin/users/status  {userId, status: 'active'|'inactive'}
  if (path === "/api/admin/users/status" && req.method === "POST") {
    const { userId, status } = await readJson(req);
    if (!["active", "inactive"].includes(status)) return json({ error: "status must be active|inactive" }, 400);
    if (!Number.isInteger(userId)) return json({ error: "userId must be an integer" }, 400);
    if (userId === auth.uid) return json({ error: "cannot change your own status" }, 400);
    const { rows } = await pg.query("UPDATE users SET status = $1 WHERE id = $2 RETURNING id, username, status", [status, userId]);
    if (!rows.length) return json({ error: "user not found" }, 404);
    if (status === "inactive") {
      await revokeAllTokens(userId);
      // kick their tunnels too
      await wg.withLock(async () => {
        for (const [pub, peer] of peers) {
          if (peer.owner !== userId) continue;
          await wg.removePeer(pub);
          peers.delete(pub);
          usedIps.delete(peer.ip);
        }
      });
    }
    console.log(`[gpn-server] admin set user ${rows[0].username} -> ${status}`);
    return json({ ok: true, user: rows[0] });
  }

  if (path === "/api/register" && req.method === "POST") {
    const body = await readJson(req);
    const publicKey = str(body.publicKey);
    if (!WG_KEY.test(publicKey)) return json({ error: "publicKey must be a valid wireguard public key" }, 400);
    const name = str(body.name).slice(0, 64);

    const peer = await wg.withLock(async () => {
      let p = peers.get(publicKey);
      if (p) {
        if (p.owner === null && auth.uid !== null) p.owner = auth.uid; // claim restored peer
        else if (!canAccess(auth, p)) throw new HttpError(403, "this key is registered to another user");
      } else {
        if (auth.role !== "admin" && auth.uid !== null) {
          const mine = [...peers.values()].filter((x) => x.owner === auth.uid).length;
          if (mine >= cfg.maxPeersPerUser) throw new HttpError(403, `peer limit reached (${cfg.maxPeersPerUser})`);
        }
        const ip = wg.allocateIp(usedIps);
        usedIps.add(ip); // reserve synchronously, before any await
        try {
          await wg.addPeer(publicKey, ip);
        } catch (e) {
          usedIps.delete(ip);
          throw e;
        }
        p = {
          publicKey,
          ip,
          name: name || (auth.uid ? `user-${auth.uid}` : "client"),
          owner: auth.uid,
          allowedGameTargets: [],
          lastSeen: Date.now(),
          createdAt: Date.now(),
        };
        peers.set(publicKey, p);
        console.log(`[gpn-server] registered peer ${p.name} -> ${ip}`);
      }
      p.lastSeen = Date.now();
      return p;
    });
    return json({
      ok: true,
      ip: peer.ip,
      serverPublicKey: serverPublicKey(),
      endpoint: `${cfg.publicEndpoint}:${cfg.wgPort}`,
      dupEndpoint: dupEndpoint(),
      subnet: cfg.wgSubnet,
    });
  }

  if (path === "/api/targets" && req.method === "POST") {
    const body = await readJson(req);
    const clientPub = req.headers.get("x-gpn-peer");
    if (!clientPub) return json({ error: "x-gpn-peer header required (your wireguard public key)" }, 400);
    if (!Array.isArray(body.targets)) return json({ error: "targets must be an array" }, 400);

    const unique = new Set<string>();
    const rejected: string[] = [];
    for (const t of body.targets) {
      const ip = str(t?.ip).trim();
      if (!isPublicIpv4(ip) || ip === cfg.publicEndpoint) rejected.push(ip);
      else unique.add(ip);
    }
    if (unique.size > cfg.maxTargets) return json({ error: `too many targets (max ${cfg.maxTargets})` }, 400);
    const next = [...unique];

    const result = await wg.withLock(async () => {
      const peer = peers.get(clientPub);
      if (!peer) throw new HttpError(404, "unknown peer — register first");
      if (!canAccess(auth, peer)) throw new HttpError(403, "not your peer");
      const prev = new Set(peer.allowedGameTargets);
      const added = next.filter((x) => !prev.has(x));
      const removed = peer.allowedGameTargets.filter((x) => !unique.has(x));
      if (added.length || removed.length) {
        await wg.setPeerTargets(clientPub, peer.ip, next); // single wg call
        peer.allowedGameTargets = next;
      }
      peer.lastSeen = Date.now();
      return { added, removed };
    });
    return json({ ok: true, routed: next, ...result, rejected });
  }

  // Latency / packet loss from THIS server to the caller's game servers (the "VPS -> game" leg).
  //   POST {targets:[{ip, port?}]}  declare what to measure (must already be on the peer's target list)
  //   GET                           current results for the caller's peer
  if (path === "/api/probe" && (req.method === "POST" || req.method === "GET")) {
    const clientPub = req.headers.get("x-gpn-peer");
    if (!clientPub) return json({ error: "x-gpn-peer header required (your wireguard public key)" }, 400);
    const peer = peers.get(clientPub);
    if (!peer) throw new HttpError(404, "unknown peer — register first");
    if (!canAccess(auth, peer)) throw new HttpError(403, "not your peer");
    if (req.method === "GET") return json({ results: probes.results(clientPub) });

    rateLimit(`probe:${ip}`, 60, 60_000);
    const body = await readJson(req);
    if (!Array.isArray(body.targets)) return json({ error: "targets must be an array" }, 400);
    const allowed = new Set(peer.allowedGameTargets);
    const list: { ip: string; port: number | null }[] = [];
    for (const t of body.targets) {
      const tip = str(t?.ip).trim();
      const port = Number.isInteger(t?.port) && t.port >= 1 && t.port <= 65535 ? (t.port as number) : null;
      if (allowed.has(tip) && !list.some((x) => x.ip === tip && x.port === port)) list.push({ ip: tip, port });
    }
    probes.watch(clientPub, list);
    return json({ ok: true, watching: Math.min(list.length, 4) });
  }

  if (path === "/api/state") {
    return json({
      auth: auth.uid ? `user:${auth.uid}` : "machine",
      peers: [...peers.values()]
        .filter((p) => canAccess(auth, p))
        .map((p) => ({
          name: p.name,
          ip: p.ip,
          targets: p.allowedGameTargets,
          lastSeenAgoMs: Date.now() - p.lastSeen,
        })),
    });
  }

  return json({ error: "not found" }, 404);
}

// periodic cleanup of stale peers: no API activity AND no WG handshake for 1h
const STALE_MS = 3_600_000;
const cleanupTimer = setInterval(() => {
  wg.withLock(async () => {
    const live = await wg.listPeers();
    const now = Date.now();
    for (const [pub, peer] of peers) {
      const handshake = (live.get(pub)?.latestHandshake ?? 0) * 1000;
      if (now - Math.max(peer.lastSeen, handshake) <= STALE_MS) continue;
      await wg.removePeer(pub);
      peers.delete(pub);
      probes.drop(pub);
      usedIps.delete(peer.ip);
      console.log(`[gpn-server] removed stale peer ${peer.name} (${peer.ip})`);
    }
  }).catch((e) => console.error("[gpn-server] peer cleanup failed:", e));
}, 600_000);

probes.start();
const dupRelay = cfg.dupPort > 0 ? await startDupRelay({ listenPort: cfg.dupPort, targetPort: cfg.wgPort, delayMs: cfg.dupDelayMs }) : null;
if (dupRelay) console.log(`[gpn-server] packet-duplication relay on udp/${cfg.dupPort} -> 127.0.0.1:${cfg.wgPort}`);
DUMMY_HASH = await hashPassword(randomBytes(8).toString("hex"));
await initDb();
await restorePeers();
const server = Bun.serve({
  port: cfg.port,
  maxRequestBodySize: 64 * 1024,
  fetch: (req, srv) =>
    handle(req, clientIp(req, srv)).catch((e) => {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.error("[gpn-server] unhandled error:", e);
      return json({ error: "internal error" }, 500);
    }),
});
console.log(`[gpn-server] listening on :${cfg.port} (wg ${cfg.wgInterface}, ${cfg.wgSubnet}, auth pg+redis)`);

async function shutdown() {
  clearInterval(cleanupTimer);
  probes.stop();
  dupRelay?.stop();
  server.stop();
  await Promise.allSettled([pg.end(), redis.quit()]);
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
