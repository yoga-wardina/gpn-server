/**
 * WireGuard management — peer CRUD via `wg` command + IP allocation.
 * Also: dynamic routing so only game-target IPs from a client egress via that
 * client's tunnel (policy routing with per-client nftables sets).
 */
import { run } from "./proc.ts";

export interface Peer {
  publicKey: string;
  ip: string; // WG vpn ip, e.g. 10.66.0.2
  name: string; // client-chosen label
  allowedGameTargets: string[]; // game ips currently routed for this client
  lastSeen: number;
  createdAt: number;
}

export class WgManager {
  constructor(
    private iface: string,
    private subnet: string
  ) {}

  async listPeers(): Promise<Map<string, { ip: string; handshakeAgo: number }>> {
    const out = await run("sudo", ["wg", "show", this.iface, "dump"]);
    const map = new Map();
    // dump format: line0 = server; peer lines: pub, pre, pres, endpoint, allowed-ips, handshake(0=none), rx, tx, keepalive
    for (const line of out.trim().split("\n").slice(1)) {
      const parts = line.split("\t");
      if (parts.length < 6) continue;
      const [pub, , , , allowed, handshake] = parts;
      // allowed-ips may be "10.66.0.2/32" or "10.66.0.2/32,1.2.3.4/32" — take first v4 /32
      const first = allowed.split(",")[0]?.split("/")[0] ?? "";
      const ip = /^(\d{1,3}\.){3}\d{1,3}$/.test(first) ? first : "";
      map.set(pub, { ip, handshakeAgo: parseInt(handshake, 10) || 0 });
    }
    return map;
  }

  async addPeer(publicKey: string, ip: string): Promise<void> {
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "allowed-ips", `${ip}/32`]);
    await run("sudo", ["wg-quick", "save", this.iface]);
  }

  async removePeer(publicKey: string): Promise<void> {
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "remove"]);
    await run("sudo", ["wg-quick", "save", this.iface]);
  }

  /** Route a game target IP so packets from this peer's tunnel go to it via WG.
   *  With allowed-ips per-peer this only affects traffic arriving from that peer. */
  async addTargetForPeer(publicKey: string, ip: string): Promise<void> {
    const peers = await this.listPeers();
    const existing = peers.get(publicKey);
    if (!existing) throw new Error("peer not found");
    // update allowed-ips = existing ip/32 + game targets
    const current = await this.getPeerAllowedIps(publicKey);
    if (current.includes(`${ip}/32`) || current.includes(ip)) return;
    const ips = [...current, `${ip}/32`];
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "allowed-ips", ips.join(",")]);
    await run("sudo", ["wg-quick", "save", this.iface]);
  }

  async removeTargetForPeer(publicKey: string, ip: string): Promise<void> {
    const current = await this.getPeerAllowedIps(publicKey);
    const ips = current.filter((x) => x !== `${ip}/32` && x !== ip);
    await run("sudo", ["wg", "set", this.iface, "peer", publicKey, "allowed-ips", ips.join(",")]);
    await run("sudo", ["wg-quick", "save", this.iface]);
  }

  private async getPeerAllowedIps(publicKey: string): Promise<string[]> {
    const out = await run("sudo", ["wg", "show", this.iface, "allowed-ips"]);
    for (const line of out.split("\n")) {
      if (line.startsWith(publicKey)) {
        // `wg show allowed-ips` separates entries with a SPACE (not comma)
        return line.split("\t")[1]?.split(/\s+/).map((s) => s.trim()).filter(Boolean) ?? [];
      }
    }
    return [];
  }

  /** Next free client IP in the subnet (10.66.0.2, .3, ...). */
  async allocateIp(used: Set<string>): Promise<string> {
    const base = this.subnet.replace(/\.0\/\d+$/, "");
    for (let i = 2; i < 255; i++) {
      const candidate = `${base}.${i}`;
      if (!used.has(candidate)) return candidate;
    }
    throw new Error("subnet exhausted");
  }
}
