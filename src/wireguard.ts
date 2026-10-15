/**
 * WireGuard management — peer CRUD via `wg` command + IP allocation.
 * All mutating operations are serialized through withLock() so concurrent
 * requests can't lose allowed-ips updates or allocate the same VPN IP.
 */
import { run } from "./proc.ts";

export interface Peer {
  publicKey: string;
  ip: string; // WG vpn ip, e.g. 10.66.0.2
  name: string; // client-chosen label
  owner: number | null; // user id; null = machine token / restored (claimable)
  allowedGameTargets: string[]; // game ips currently in this peer's allowed-ips
  lastSeen: number;
  createdAt: number;
}

export interface WgPeerInfo {
  ip: string; // the peer's own /32 (first allowed-ip)
  targets: string[]; // remaining allowed-ips (game targets)
  latestHandshake: number; // unix seconds, 0 = never
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

export class WgManager {
  private queue: Promise<unknown> = Promise.resolve();
  private saveTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private iface: string,
    private subnet: string
  ) {}

  /** Run fn after all previously queued WG operations finish. */
  withLock<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => {});
    return next;
  }

  async listPeers(): Promise<Map<string, WgPeerInfo>> {
    const out = await run("sudo", ["wg", "show", this.iface, "dump"]);
    const map = new Map<string, WgPeerInfo>();
    // dump format: line0 = server; peer lines: pub, psk, endpoint, allowed-ips, handshake(unix, 0=none), rx, tx, keepalive
    for (const line of out.trim().split("\n").slice(1)) {
      const parts = line.split("\t");
      if (parts.length < 6) continue;
      const [pub, , , allowed, handshake] = parts;
      const ips = (allowed ?? "")
        .split(",")
        .map((s) => s.split("/")[0]!.trim())
        .filter((s) => IPV4.test(s));
      map.set(pub!, {
        ip: ips[0] ?? "",
        targets: ips.slice(1),
        latestHandshake: parseInt(handshake ?? "0", 10) || 0,
      });
    }
    return map;
  }

  /** Caller must hold the lock. */
  async addPeer(publicKey: string, ip: string): Promise<void> {
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "allowed-ips", `${ip}/32`]);
    this.scheduleSave();
  }

  /** Caller must hold the lock. */
  async removePeer(publicKey: string): Promise<void> {
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "remove"]);
    this.scheduleSave();
  }

  /** Replace a peer's allowed-ips with its own /32 plus the given targets in ONE wg call.
   *  Deliberately does not `wg-quick save`: targets are transient and must not be persisted. */
  async setPeerTargets(publicKey: string, peerIp: string, targets: string[]): Promise<void> {
    const ips = [`${peerIp}/32`, ...targets.map((t) => `${t}/32`)];
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "allowed-ips", ips.join(",")]);
  }

  /** Debounced `wg-quick save` (peer membership changes only). */
  private scheduleSave() {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      this.withLock(() => run("sudo", ["wg-quick", "save", this.iface])).catch((e) =>
        console.error("[gpn-server] wg-quick save failed:", e)
      );
    }, 2000);
  }

  /** Next free client IP in the subnet (10.66.0.2, .3, ...). Synchronous so
   *  allocation + reservation can't interleave with another request. */
  allocateIp(used: Set<string>): string {
    const base = this.subnet.replace(/\.0\/\d+$/, "");
    for (let i = 2; i < 255; i++) {
      const candidate = `${base}.${i}`;
      if (!used.has(candidate)) return candidate;
    }
    throw new Error("subnet exhausted");
  }
}
