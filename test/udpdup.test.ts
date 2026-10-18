import { expect, test } from "bun:test";
import { startDupRelay } from "../src/udpdup";

const wgPacket = (n: number) => {
  const b = new Uint8Array(40);
  b[0] = 4; // WireGuard transport data
  b[8] = n;
  return b;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test("duplicates both directions, echoes probes, ignores junk", async () => {
  // fake WireGuard: counts what it receives and answers each packet once
  const seen: number[] = [];
  const wg = await Bun.udpSocket({
    port: 0,
    hostname: "127.0.0.1",
    socket: {
      data(s, buf, port, addr) {
        seen.push(new Uint8Array(buf)[8]);
        s.send(new Uint8Array(buf), port, addr);
      },
    },
  });
  const relay = await startDupRelay({ listenPort: 0, listenHost: "127.0.0.1", targetPort: wg.port, delayMs: 2 });

  const got: number[] = [];
  const probes: number[] = [];
  const client = await Bun.udpSocket({
    port: 0,
    hostname: "127.0.0.1",
    socket: {
      data(_s, buf) {
        const b = new Uint8Array(buf);
        if (b[0] === 0x47) probes.push(b[4]);
        else got.push(b[8]);
      },
    },
  });

  // a probe is echoed
  client.send(new Uint8Array([0x47, 0x50, 0x4e, 0x50, 7]), relay.port, "127.0.0.1");
  // junk is dropped, not forwarded
  client.send(new Uint8Array([9, 9, 9, 9, 9]), relay.port, "127.0.0.1");
  // the first WG packet creates the client's upstream socket; later ones flow straight through
  client.send(wgPacket(1), relay.port, "127.0.0.1");
  await sleep(150);
  client.send(wgPacket(2), relay.port, "127.0.0.1");
  client.send(wgPacket(2), relay.port, "127.0.0.1"); // the client's own duplicate: both reach WireGuard
  await sleep(250);

  expect(probes).toEqual([7]);
  expect(seen.filter((n) => n === 1)).toHaveLength(1);
  expect(seen.filter((n) => n === 2)).toHaveLength(2);
  // every reply the fake WG sent came back to the client twice
  expect(got.filter((n) => n === 1)).toHaveLength(2);
  expect(got.filter((n) => n === 2)).toHaveLength(4);
  const st = relay.stats();
  expect(st.clients).toBe(1);
  expect(st.dropped).toBe(1);
  expect(st.probes).toBe(1);

  client.close();
  relay.stop();
  wg.close();
});
