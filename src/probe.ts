/**
 * Path probes: measures latency and packet loss from THIS server to a client's game servers, so the
 * client can show "VPS -> game server" next to its own "me -> VPS" measurement.
 *
 * Per target the server probes every few seconds while the client keeps asking (watch() expires after
 * WATCH_TTL_MS): a TCP connect to the game's port when known (connect time ~ one round trip; works for
 * hosts that drop ICMP), else an ICMP echo via the `ping` binary. Targets are limited to IPs already
 * registered on the caller's peer, and to a handful per peer, so this can't be used as a scanner.
 */
import { connect } from "node:net";
import { run } from "./proc.ts";

const WATCH_TTL_MS = 45_000;
const INTERVAL_MS = 2_000;
const WINDOW = 30; // samples kept per target
const TCP_TIMEOUT_MS = 1_500;
const MAX_CONCURRENT = 8;

export interface Sample {
  ok: boolean;
  /** round trip in ms (only meaningful when ok) */
  rtt: number;
}

export interface Stats {
  last: number | null;
  avg: number | null;
  min: number | null;
  max: number | null;
  /** mean absolute difference between consecutive round trips */
  jitter: number | null;
  /** percentage of failed probes in the window */
  lossPct: number;
  /** recent round trips (ms), null where the probe was lost */
  samples: (number | null)[];
}

export function computeStats(samples: Sample[]): Stats {
  const rtts = samples.filter((s) => s.ok).map((s) => s.rtt);
  const round = (n: number) => Math.round(n * 10) / 10;
  let jitter: number | null = null;
  if (rtts.length >= 2) {
    let sum = 0;
    for (let i = 1; i < rtts.length; i++) sum += Math.abs(rtts[i]! - rtts[i - 1]!);
    jitter = round(sum / (rtts.length - 1));
  }
  const last = samples.length ? (samples[samples.length - 1]!.ok ? round(samples[samples.length - 1]!.rtt) : null) : null;
  return {
    last,
    avg: rtts.length ? round(rtts.reduce((a, b) => a + b, 0) / rtts.length) : null,
    min: rtts.length ? round(Math.min(...rtts)) : null,
    max: rtts.length ? round(Math.max(...rtts)) : null,
    jitter,
    lossPct: samples.length ? round((samples.filter((s) => !s.ok).length / samples.length) * 100) : 0,
    samples: samples.map((s) => (s.ok ? round(s.rtt) : null)),
  };
}

/** TCP connect time. A refused connection still proves the host answered, so it counts as a reply. */
export function tcpProbe(ip: string, port: number, timeoutMs = TCP_TIMEOUT_MS): Promise<Sample> {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ ok, rtt: ok ? performance.now() - t0 : 0 });
    };
    const sock = connect({ host: ip, port });
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", (e: NodeJS.ErrnoException) => finish(e.code === "ECONNREFUSED"));
  });
}

/** One ICMP echo through the system `ping` (iputils / busybox). */
export async function icmpProbe(ip: string): Promise<Sample> {
  try {
    const out = await run("ping", ["-n", "-c", "1", "-W", "1", ip], 3_000);
    const m = /time[=<]([\d.]+)\s*ms/.exec(out);
    return m ? { ok: true, rtt: parseFloat(m[1]!) } : { ok: false, rtt: 0 };
  } catch {
    return { ok: false, rtt: 0 };
  }
}

interface State {
  ip: string;
  port: number | null;
  samples: Sample[];
  expires: number;
  inflight: boolean;
  nextAt: number;
}

export class ProbeManager {
  private peers = new Map<string, Map<string, State>>(); // peer public key -> "ip:port" -> state
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = 0;

  constructor(
    private maxPerPeer = 4,
    private tcp: typeof tcpProbe = tcpProbe,
    private icmp: typeof icmpProbe = icmpProbe
  ) {}

  start() {
    if (!this.timer) this.timer = setInterval(() => this.tick(), 500);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** (Re)declare which targets this peer cares about; existing history is kept. */
  watch(peerKey: string, targets: { ip: string; port: number | null }[], now = Date.now()) {
    const next = new Map<string, State>();
    const prev = this.peers.get(peerKey);
    for (const t of targets.slice(0, this.maxPerPeer)) {
      const key = `${t.ip}:${t.port ?? 0}`;
      const st = prev?.get(key) ?? { ip: t.ip, port: t.port, samples: [], expires: 0, inflight: false, nextAt: 0 };
      st.expires = now + WATCH_TTL_MS;
      next.set(key, st);
    }
    this.peers.set(peerKey, next);
  }

  results(peerKey: string) {
    const out = [];
    for (const st of this.peers.get(peerKey)?.values() ?? []) {
      out.push({ ip: st.ip, port: st.port, method: st.port ? "tcp" : "icmp", ...computeStats(st.samples) });
    }
    return out;
  }

  drop(peerKey: string) {
    this.peers.delete(peerKey);
  }

  private tick(now = Date.now()) {
    for (const [peerKey, states] of this.peers) {
      for (const [key, st] of states) {
        if (now > st.expires) {
          states.delete(key);
          continue;
        }
        if (st.inflight || now < st.nextAt || this.running >= MAX_CONCURRENT) continue;
        st.inflight = true;
        st.nextAt = now + INTERVAL_MS;
        this.running++;
        (st.port ? this.tcp(st.ip, st.port) : this.icmp(st.ip))
          .then((s) => {
            st.samples.push(s);
            if (st.samples.length > WINDOW) st.samples.shift();
          })
          .catch(() => {})
          .finally(() => {
            st.inflight = false;
            this.running--;
          });
      }
      if (!states.size) this.peers.delete(peerKey);
    }
  }
}
