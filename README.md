# GPN Server

VPS-side GPN API. Clients register their WireGuard public key, then push the
game-server IPs they detect; the server manages each client's WG peer
allowed-ips so only game traffic from that peer gets routed/forwarded.

## Run

```bash
bun install
# edit server.config.json (apiToken required)
sudo bun run src/main.ts     # needs sudo for wg commands
```

WireGuard interface must exist (`/etc/wireguard/wg0.conf` with Address
10.66.0.1/24, port 51820, ip_forward + MASQUERADE).

## API

- `GET /api/health` — no auth
- `POST /api/register` — `{publicKey, name}` → `{ip, serverPublicKey, endpoint, subnet}`
- `POST /api/targets` — `{targets:[{ip,port,proto}]}` + headers
  `Authorization: Bearer <token>` and `x-gpn-peer: <client pub key>`
- `GET /api/state` — debug view

Auth token lives in `server.config.json` (chmod 600, gitignored).
