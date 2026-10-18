import type { udp } from "bun";

/**
 * Packet-duplication relay for the WireGuard UDP port.
 *
 * Clients on a lossy link send every WireGuard datagram twice (a few ms apart) to this relay;
 * it forwards both copies to the local WireGuard port, and WireGuard's replay protection drops the
 * second one. In the other direction the relay sends every reply to the client twice. A packet is
 * then only lost if both copies are, which hides random loss from TCP (no retransmit stalls).
 *
 * Each client address gets its own upstream socket, so WireGuard sees a stable, distinct source per
 * client and keeps routing replies to the right place. Probe packets (magic "GPNP") are echoed so a
 * client can measure its real UDP loss to this host before turning duplication on.
 */

const PROBE_MAGIC = [0x47, 0x50, 0x4e, 0x50]; // "GPNP"
const MAX_PROBE_LEN = 64; // echo no more than we receive, and keep it small (no amplification)
const WG_MIN_LEN = 32; // smallest WireGuard message (keepalive)
const WG_MAX_LEN = 2048;

export interface DupOptions {
  listenPort: number;
  listenHost?: string;
  targetPort: number;
  targetHost?: string;
  /** gap between the two copies sent to a client (ms); 0 = back to back */
  delayMs?: number;
  maxClients?: number;
  idleMs?: number;
}

export interface DupStats {
  clients: number;
  fromClients: number;
  toClients: number;
  probes: number;
  dropped: number;
  /** upstream packets that arrived with both copies / with only one (so the other was lost on the way) */
  upPairs: number;
  upSingles: number;
}

export interface DupRelay {
  stop(): void;
  stats(): DupStats;
  port: number;
}

type UdpSock = udp.Socket<"buffer">;

interface Client {
  addr: string;
  port: number;
  up: UdpSock;
  last: number;
}

const isProbe = (b: Uint8Array) => b.length >= PROBE_MAGIC.length && b.length <= MAX_PROBE_LEN && PROBE_MAGIC.every((v, i) => b[i] === v);
/** WireGuard messages start with a type byte 1..4 followed by three zero bytes. */
const looksLikeWireguard = (b: Uint8Array) => b.length >= WG_MIN_LEN && b.length <= WG_MAX_LEN && b[0] >= 1 && b[0] <= 4 && b[1] === 0 && b[2] === 0 && b[3] === 0;

export async function startDupRelay(o: DupOptions): Promise<DupRelay> {
  const delay = Math.max(0, Math.min(o.delayMs ?? 3, 50));
  const maxClients = o.maxClients ?? 256;
  const idleMs = o.idleMs ?? 180_000;
  const targetHost = o.targetHost ?? "127.0.0.1";
  const clients = new Map<string, Client>();
  const st = { fromClients: 0, toClients: 0, probes: 0, dropped: 0, upPairs: 0, upSingles: 0 };
  // fingerprints of recent upstream packets: a packet seen twice = both copies arrived, once = one was lost
  const recent = new Map<string, { t: number; n: number }>();
  const PAIR_WINDOW_MS = 300;
  const note = (key: string, data: Uint8Array) => {
    const k = `${key}/${Bun.hash(data)}`;
    const e = recent.get(k);
    if (e) e.n++;
    else recent.set(k, { t: Date.now(), n: 1 });
  };
  const settle = () => {
    const now = Date.now();
    for (const [k, e] of recent) {
      if (now - e.t < PAIR_WINDOW_MS) continue;
      if (e.n >= 2) st.upPairs++;
      else st.upSingles++;
      recent.delete(k);
    }
  };
  const settler = setInterval(settle, 150);

  const sendTwice = (sock: UdpSock, data: Uint8Array, port: number, addr: string) => {
    sock.send(data, port, addr);
    st.toClients++;
    const copy = data.slice(); // the buffer may be reused by the socket after this callback
    if (delay === 0) sock.send(copy, port, addr);
    else setTimeout(() => { try { sock.send(copy, port, addr); } catch { /* socket closed */ } }, delay);
  };

  const pub: UdpSock = await Bun.udpSocket({
    port: o.listenPort,
    hostname: o.listenHost ?? "0.0.0.0",
    socket: {
      data(_s, buf, port, addr) {
        const data = new Uint8Array(buf);
        if (isProbe(data)) {
          st.probes++;
          pub.send(data, port, addr);
          return;
        }
        if (!looksLikeWireguard(data)) { st.dropped++; return; }
        const key = `${addr}:${port}`;
        let c = clients.get(key);
        if (!c) {
          if (clients.size >= maxClients) { st.dropped++; return; }
          // reserve the slot synchronously so a burst from one new client creates one socket
          const entry: Client = { addr, port, up: undefined as unknown as UdpSock, last: Date.now() };
          clients.set(key, entry);
          Bun.udpSocket({
            connect: { port: o.targetPort, hostname: targetHost },
            socket: {
              data(_u, reply) {
                const e = clients.get(key);
                if (!e) return;
                e.last = Date.now();
                sendTwice(pub, new Uint8Array(reply), e.port, e.addr);
              },
            },
          }).then((sock) => {
            entry.up = sock;
            // the packet that created the entry (ones racing in before the socket is ready are dropped; WireGuard retries)
            sock.send(data);
          }, () => clients.delete(key));
          st.fromClients++;
          note(key, data);
          return;
        }
        c.last = Date.now();
        st.fromClients++;
        note(key, data);
        if (c.up) c.up.send(data);
      },
    },
  });

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, c] of clients) {
      if (now - c.last > idleMs) {
        try { c.up?.close(); } catch { /* already closed */ }
        clients.delete(k);
      }
    }
  }, 30_000);

  return {
    port: pub.port,
    stats: () => ({ clients: clients.size, ...st }),
    stop() {
      clearInterval(sweeper);
      clearInterval(settler);
      for (const c of clients.values()) { try { c.up?.close(); } catch { /* ignore */ } }
      clients.clear();
      pub.close();
    },
  };
}
