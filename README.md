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

## Config (server.config.json)

Required: `apiToken`, `publicEndpoint`, `db.password` (or env `GPN_DB_PASSWORD`).
Optional: `port`, `wgInterface`, `wgPort` (51820), `wgSubnet`, `maxTargets` (64),
`maxPeersPerUser` (5), `inviteCode` (if set, registration requires it),
`db.*`, `redis.*`.

First run creates user `admin`; its password is written to
`admin-initial-password.txt` (0600). Change it with `POST /api/auth/password`.

## API

- `GET /api/health` — no auth
- `POST /api/auth/{register,login,refresh,logout}` — public, rate limited
- `POST /api/auth/password`, `GET /api/auth/me` — Bearer
- `GET /api/admin/users`, `POST /api/admin/users/status` — admin role
- `POST /api/register` — `{publicKey, name}` → `{ip, serverPublicKey, endpoint, subnet}`
- `POST /api/targets` — `{targets:[{ip}]}` + `x-gpn-peer: <client pub key>`;
  only public IPv4 accepted, peer must belong to the caller
- `GET /api/state` — own peers (all peers for admins)
