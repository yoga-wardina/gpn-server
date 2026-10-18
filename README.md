# GPN Server

The VPS side of GPN (a private "game network"). Your PC's client opens a WireGuard tunnel to this
VPS and sends only game traffic through it; this server

- keeps user accounts (Postgres) and sessions (Redis),
- hands each client a WireGuard peer (a VPN IP in `10.66.0.0/24`),
- manages each peer's `allowed-ips` on the server's WireGuard interface as the client reports the game
  servers it detects.

```
 your PC ──WireGuard (UDP 51820)──▶ VPS (wg0, NAT) ──▶ game server
    │                                  ▲
    └──HTTPS API (Caddy → :9090)───────┘   accounts, peer registration, targets
```

> Scope: built for personal / small-group use. The server does **not** firewall which destinations an
> authenticated peer may reach through the tunnel (see [Known limitations](#known-limitations)).

---

## Contents

1. [What you need](#1-what-you-need)
2. [Step-by-step deployment](#2-step-by-step-deployment)
3. [Configuration reference](#3-configuration-reference)
4. [API reference](#4-api-reference)
   - [4b. Packet-duplication relay (optional)](#4b-packet-duplication-relay-optional)
5. [Operations](#5-operations)
6. [Security notes](#6-security-notes)
7. [Troubleshooting](#7-troubleshooting)
8. [Known limitations](#known-limitations)

---

## 1. What you need

| Item | Notes |
|---|---|
| A Linux VPS with a public IPv4 | Examples below are for Ubuntu 22.04/24.04 or Debian 12. Needs root. |
| A domain name (recommended) | e.g. `gpn.example.com` pointing at the VPS. Clients require `https://`, and Caddy gets the certificate automatically. |
| Open ports | `22/tcp` (SSH), `80/tcp` + `443/tcp` (Caddy), `51820/udp` (WireGuard). **Not** `9090`. |
| Software | WireGuard, PostgreSQL, Redis, [Bun](https://bun.sh), Caddy (or any TLS reverse proxy), `sudo`. |

Values used throughout — replace them with yours:

| Placeholder | Meaning |
|---|---|
| `<VPS_IP>` | the VPS's public IPv4 |
| `gpn.example.com` | your API domain |
| `eth0` | the VPS's public network interface (find it with `ip route get 1.1.1.1`, look for `dev …`) |
| `/opt/gpn-server` | where the server code lives |

---

## 2. Step-by-step deployment

Run everything as root (or prefix with `sudo`).

### Step 1 — Base packages

```bash
apt update && apt upgrade -y
apt install -y wireguard postgresql redis-server sudo ufw curl unzip openssl
```

### Step 2 — Enable IP forwarding

The VPS must route packets between the tunnel and the internet.

```bash
cat > /etc/sysctl.d/99-gpn.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl --system
sysctl net.ipv4.ip_forward        # → net.ipv4.ip_forward = 1
```

### Step 3 — WireGuard

Generate the server key pair. The server reads the **public** key from exactly
`/etc/wireguard/server.pub` and hands it to clients, so keep these names.

```bash
umask 077
mkdir -p /etc/wireguard
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
cat /etc/wireguard/server.pub     # the public key clients will receive
```

Find your public interface name (used for NAT below):

```bash
ip route get 1.1.1.1              # …dev eth0…  ← this name
```

Create `/etc/wireguard/wg0.conf` (replace `eth0` if yours differs and paste the private key):

```ini
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = <contents of /etc/wireguard/server.key>
SaveConfig = false

# NAT: let tunnel clients reach the internet through this VPS
PostUp   = iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostUp   = iptables -I FORWARD -i wg0 -j ACCEPT
PostUp   = iptables -I FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

There are **no `[Peer]` sections** — the server adds peers at runtime and persists them with
`wg-quick save`.

Start it now and on every boot:

```bash
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
wg show wg0                       # interface up, listening on 51820
```

> `ListenPort` must match `wgPort` in the server config (default `51820`).

### Step 4 — PostgreSQL

Create the database and user. The `users` table is created automatically on first start.

```bash
# pick a strong password and keep it for step 7
DB_PASS=$(openssl rand -hex 24); echo "$DB_PASS"

sudo -u postgres psql <<EOF
CREATE USER gpn WITH PASSWORD '$DB_PASS';
CREATE DATABASE gpn OWNER gpn;
EOF
```

Postgres listens on `127.0.0.1:5432` by default — leave it that way.

### Step 5 — Redis

Redis holds access/refresh tokens. The server config supports only host/port (no Redis password), so
keep Redis on loopback:

```bash
grep -E '^(bind|protected-mode)' /etc/redis/redis.conf   # expect: bind 127.0.0.1 -::1 / protected-mode yes
systemctl enable --now redis-server
redis-cli ping                                            # → PONG
```

### Step 6 — Install Bun and the server code

```bash
curl -fsSL https://bun.sh/install | bash        # installs to ~/.bun/bin (root: /root/.bun/bin/bun)
/root/.bun/bin/bun --version
```

Put the `gpn-server` folder on the VPS at `/opt/gpn-server`. Either:

```bash
# from your PC (Git Bash / WSL / PowerShell with scp), from the folder that contains gpn-server/
scp -r gpn-server root@<VPS_IP>:/opt/            # then on the VPS: rm -rf /opt/gpn-server/node_modules
```

or `git clone` it from your private repo. Then install dependencies:

```bash
cd /opt/gpn-server
/root/.bun/bin/bun install --production
```

> Run the server **from source with Bun** (as below). Don't use `bun run build:linux`: the config and
> the admin-password file are located relative to the source tree and won't resolve inside a compiled binary.

### Step 7 — Configure

```bash
cd /opt/gpn-server
API_TOKEN=$(openssl rand -hex 32)

cat > server.config.json <<EOF
{
  "apiToken": "$API_TOKEN",
  "port": 9090,
  "publicEndpoint": "<VPS_IP>",
  "wgInterface": "wg0",
  "wgPort": 51820,
  "wgSubnet": "10.66.0.0/24",
  "db": { "password": "$DB_PASS" }
}
EOF
chmod 600 server.config.json
```

- `publicEndpoint` is what clients dial for WireGuard (`<VPS_IP>:51820`). It must be the VPS's **public IP or
  hostname** (clients don't reach the tunnel through Caddy).
- `apiToken` is also the "machine token": a shared admin credential that bypasses user accounts. Treat it
  like a root password and store it somewhere safe.
- Add `"inviteCode": "<secret>"` if you want registration to require a code. **Without it, anyone who finds
  your URL can create an account** and get a tunnel.
- All options are in the [configuration reference](#3-configuration-reference).

### Step 8 — First run in the foreground

```bash
cd /opt/gpn-server
/root/.bun/bin/bun run src/main.ts
```

Expected output:

```
[gpn-server] first user 'admin' created; initial password written to /opt/gpn-server/admin-initial-password.txt
[gpn-server] listening on :9090 (wg wg0, 10.66.0.0/24, auth pg+redis)
```

In a second shell:

```bash
curl -s http://127.0.0.1:9090/api/health          # {"ok":true,"ts":...}
cat /opt/gpn-server/admin-initial-password.txt     # username: admin / password: <generated>
```

Common start-up failures: see [Troubleshooting](#7-troubleshooting). Stop it with `Ctrl+C`.

### Step 9 — Run it as a service (systemd)

```bash
cat > /etc/systemd/system/gpn-server.service <<'EOF'
[Unit]
Description=GPN server (accounts + WireGuard peer management)
After=network-online.target wg-quick@wg0.service postgresql.service redis-server.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=/opt/gpn-server
ExecStart=/root/.bun/bin/bun run src/main.ts
Restart=on-failure
RestartSec=3
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now gpn-server
systemctl status gpn-server --no-pager
journalctl -u gpn-server -f                      # live logs
```

Why root: the server runs `sudo wg …` / `sudo wg-quick …` and reads `/etc/wireguard/server.pub`
directly, both of which need root (and `sudo` must be installed). Don't add `NoNewPrivileges=`: it stops
`sudo` from working.

The unit starts after WireGuard on purpose: on start the server rebuilds its peer table from
`wg show wg0 dump`.

### Step 10 — HTTPS reverse proxy (Caddy)

Point a DNS **A record** `gpn.example.com → <VPS_IP>` first, then:

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

cat > /etc/caddy/Caddyfile <<'EOF'
gpn.example.com {
    reverse_proxy 127.0.0.1:9090
}
EOF
systemctl reload caddy
```

Caddy obtains and renews the certificate itself (ports 80 and 443 must be reachable). Caddy sets
`X-Forwarded-For`, which the server uses for per-IP rate limiting.

### Step 11 — Firewall

The API port `9090` must **not** be reachable from the internet: the server listens on all interfaces and
trusts `X-Forwarded-For`, so a direct connection would bypass HTTPS and let clients spoof their IP for rate
limiting.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp        # SSH — keep this or you lock yourself out
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw enable
ufw status verbose
```

If tunnel clients can connect but have no internet through the VPS and you use ufw, set
`DEFAULT_FORWARD_POLICY="ACCEPT"` in `/etc/default/ufw` and `ufw reload`.

Also open the same ports in your cloud provider's firewall / security group if it has one.

### Step 12 — Verify end to end

```bash
# 1. HTTPS + proxy
curl -s https://gpn.example.com/api/health

# 2. Log in as admin (use the password from admin-initial-password.txt)
curl -s -X POST https://gpn.example.com/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<PASSWORD>"}'
# → {"ok":true,"user":{...},"accessToken":"…","refreshToken":"…"}

# 3. Change the admin password immediately, then delete the file
ACCESS=<accessToken from above>
curl -s -X POST https://gpn.example.com/api/auth/password \
  -H "authorization: Bearer $ACCESS" -H 'content-type: application/json' \
  -d '{"oldPassword":"<PASSWORD>","newPassword":"<a long new password>"}'
rm /opt/gpn-server/admin-initial-password.txt

# 4. Register a throw-away WireGuard peer
PUB=$(wg genkey | wg pubkey)
curl -s -X POST https://gpn.example.com/api/register \
  -H "authorization: Bearer $ACCESS" -H 'content-type: application/json' \
  -d "{\"publicKey\":\"$PUB\",\"name\":\"test\"}"
# → {"ok":true,"ip":"10.66.0.2","serverPublicKey":"…","endpoint":"<VPS_IP>:51820","subnet":"10.66.0.0/24"}
wg show wg0                                       # the test peer is listed
```

The test peer is cleaned up automatically after an hour without activity, or remove it now with
`wg set wg0 peer $PUB remove && wg-quick save wg0`.

### Step 13 — Connect a client

In the desktop client: set the server URL to `https://gpn.example.com`, sign in (or register — with the
invite code if you set one), add your game and launch it. The client needs WireGuard for Windows installed
and must run as administrator. After a game connects, `wg show wg0` on the VPS shows the peer with a recent
handshake and its game IPs in `allowed ips`.

---

## 3. Configuration reference

`server.config.json` (in the project root, not committed, chmod 600).

| Key | Default | Description |
|---|---|---|
| `apiToken` | — **required** | Shared machine token; works as an admin Bearer token. |
| `publicEndpoint` | — **required** | Public IP/hostname clients use for WireGuard. Returned by `/api/register` as `<publicEndpoint>:<wgPort>`. |
| `db.password` | — **required** | Postgres password. May instead be set via the `GPN_DB_PASSWORD` environment variable. |
| `db.host` / `db.port` | `127.0.0.1` / `5432` | |
| `db.name` / `db.user` | `gpn` / `gpn` | |
| `redis.host` / `redis.port` | `127.0.0.1` / `6379` | No password option — keep Redis on loopback. |
| `port` | `9090` | HTTP listen port (behind the reverse proxy). |
| `wgInterface` | `wg0` | WireGuard interface name. |
| `wgPort` | `51820` | WireGuard UDP port advertised to clients (must match `ListenPort`). |
| `dupPort` | `0` (off) | UDP port of the **packet-duplication relay** (e.g. `51821`). Clients on a lossy link send each WireGuard packet twice to it; it forwards both to WireGuard (which drops the repeat) and sends replies back twice. Open it in the firewall: `ufw allow 51821/udp`. Also answers the client's UDP loss test. Changing it needs a restart. |
| `dupDelayMs` | `3` | Gap between the two copies the relay sends back to a client (0–50 ms). |
| `wgSubnet` | `10.66.0.0/24` | Client addresses are allocated as `.2`, `.3`, … (`.1` is the server). |
| `maxTargets` | `64` | Max game IPs per peer. |
| `maxPeersPerUser` | `5` | Max WireGuard peers a non-admin user may register. |
| `inviteCode` | unset | If set, `POST /api/auth/register` must include a matching `inviteCode`. |

Environment: `GPN_DB_PASSWORD` (see above). Old keys `mode`, `targetTtlMs`, `wgPrivateKeyFile` are ignored.

Behavior worth knowing:

- Access tokens last 24 h, refresh tokens 30 d (rotated on every refresh).
- Usernames: 3–24 characters `[a-zA-Z0-9_-]`; passwords 8–128 characters.
- Rate limits per client IP: register 5/hour, login 10/min, refresh 30/min, password change 10/min.
- Request bodies are limited to 64 KB.
- A peer with no API activity **and** no WireGuard handshake for 1 hour is removed automatically.
- Latency probes (`/api/probe`) run only while a client keeps asking (they stop 45 s after the last request), one
  probe per target every 2 s, over the last 30 samples. With a known port it's a TCP connect (works for hosts that
  drop ICMP; a refused connection still counts as a reply); otherwise one ICMP echo through the system `ping`
  (`apt install iputils-ping` if it's missing). Only IPs already registered on the caller's peer can be probed.
- Game targets must be public IPv4 addresses (private, loopback, link-local, CGNAT, multicast and the
  server's own `publicEndpoint` are rejected).

---

## 4. API reference

All bodies are JSON. "Bearer" means `Authorization: Bearer <accessToken>` (or the `apiToken`).

| Method & path | Auth | Description |
|---|---|---|
| `GET /api/health` | none | `{ok, ts, dup}` — `dup` is the relay's `host:port`, or `null` when `dupPort` is 0 |
| `POST /api/auth/register` | none | `{username, password[, inviteCode]}` → `{user, accessToken, refreshToken}` |
| `POST /api/auth/login` | none | `{username, password}` → `{user, accessToken, refreshToken}` |
| `POST /api/auth/refresh` | none | `{refreshToken}` → new `{accessToken, refreshToken}` (old refresh token is consumed) |
| `POST /api/auth/logout` | optional | `{refreshToken}` revokes it (and the Bearer access token if given) |
| `POST /api/auth/password` | Bearer | `{oldPassword, newPassword}` → revokes all sessions, returns new tokens |
| `GET /api/auth/me` | Bearer | current user |
| `POST /api/register` | Bearer | `{publicKey, name}` → `{ip, serverPublicKey, endpoint, subnet}`; idempotent per key |
| `POST /api/targets` | Bearer + `x-gpn-peer: <public key>` | `{targets:[{ip}]}` → `{routed, added, removed, rejected}` |
| `POST /api/probe` | Bearer + `x-gpn-peer` | `{targets:[{ip, port?}]}` — start measuring latency/loss **from this server** to game servers already on your target list (max 4) |
| `GET /api/probe` | Bearer + `x-gpn-peer` | latest results per target: `{ip, port, method, last, avg, min, max, jitter, lossPct, samples[]}` |
| `GET /api/state` | Bearer | your peers (all peers for admins) |
| `GET /api/admin/users` | admin | list users |
| `POST /api/admin/users/status` | admin | `{userId, status:"active"\|"inactive"}` — inactive revokes tokens and removes that user's peers |

Admin examples:

```bash
BASE=https://gpn.example.com
TOKEN=<an admin accessToken, or the apiToken>

curl -s $BASE/api/admin/users -H "authorization: Bearer $TOKEN"

curl -s -X POST $BASE/api/admin/users/status -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"userId":2,"status":"inactive"}'
```

---

## 4b. Packet-duplication relay (optional)

**What it is.** An extra UDP listener inside the existing `gpn-server` process (no second server, no new
dependency). Clients on a lossy link send every WireGuard datagram to it **twice**; it forwards both copies to
the local WireGuard port (`wgPort`), whose replay protection drops the repeat, and it sends WireGuard's replies
back to the client twice. A packet is lost only if both copies are. It also echoes small `GPNP` probe packets so
the desktop app can measure real UDP loss. It is **off unless `dupPort` is set**, and nothing else changes when
it is off.

```
client WireGuard -> client proxy --(x2)--> VPS :dupPort (relay) --> 127.0.0.1:wgPort (WireGuard) --> NAT --> game
                                   <--(x2)--
```

The relay only forwards datagrams that look like WireGuard messages (type byte 1-4, 32-2048 bytes) and
probes (<= 64 bytes, echoed back at the same size, so no amplification). At most 256 client addresses at a time,
idle ones dropped after 3 minutes.

### Deploy (runbook for an automated agent)

Assumptions: the server lives in `/opt/gpn-server`, runs as the systemd unit `gpn-server`, Bun is at
`/root/.bun/bin/bun`, WireGuard listens on `51820` (the default `wgPort`), `ufw` is the firewall. Use another
free UDP port than `51821` if it is taken; use the same number in every step.

1. **Update the code** (from the `udp-dup` branch of this repo). Copy `src/` (including the new
   `src/udpdup.ts`) and `test/` over `/opt/gpn-server`. Do **not** overwrite `server.config.json`.
   There are no new dependencies, so `bun install` is not needed (running `bun install --production` is harmless).
2. **Enable it in the config.** Edit `/opt/gpn-server/server.config.json` and add two keys to the top-level
   object, keeping everything else:

   ```json
   "dupPort": 51821,
   "dupDelayMs": 3
   ```

   Validate: `python3 -c "import json;json.load(open('/opt/gpn-server/server.config.json'))"` must print nothing.
3. **Open the port.**

   ```bash
   ufw allow 51821/udp
   ufw status | grep 51821
   ```

   If the VPS provider has a separate cloud firewall / security group, open **UDP 51821** inbound there as well
   (the most common reason the client test reports "no reply").
4. **Restart and check the log.**

   ```bash
   systemctl restart gpn-server
   sleep 2
   systemctl is-active gpn-server                      # -> active
   journalctl -u gpn-server -n 30 --no-pager | grep "packet-duplication"
   # -> [gpn-server] packet-duplication relay on udp/51821 -> 127.0.0.1:51820
   ss -lunp | grep 51821                               # a bun process listens on 0.0.0.0:51821
   ```

5. **Check the public API advertises it.**

   ```bash
   curl -s https://<server-domain>/api/health          # -> {"ok":true,"ts":...,"dup":"<publicEndpoint>:51821"}
   ```

   `"dup":null` means `dupPort` was not read (wrong key / not restarted).
6. **Check the relay answers probes** (from any machine with Python 3; replace the host):

   ```bash
   python3 - <<'EOF'
   import socket
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
   p = b"GPNP" + bytes(9)
   s.sendto(p, ("<publicEndpoint>", 51821))
   print("echo ok" if s.recvfrom(64)[0] == p else "bad echo")
   EOF
   ```

   `socket.timeout` = the port is blocked (ufw / cloud firewall) or the service is not running.
7. **Optional unit test on the server** (needs the dev files from step 1): `cd /opt/gpn-server && /root/.bun/bin/bun test test/udpdup.test.ts` -> `1 pass`.

Done criteria: steps 4-6 all succeed. Existing peers, targets and the WireGuard port are unaffected.

### Using it from the desktop app

On the PC (app branch `udp-dup`): *Settings -> Packet loss protection -> Run test* reports UDP loss with one copy
vs. two. If real loss shows up, tick **Enabled**; it applies the next time the tunnel starts. See the desktop
README, section *Packet duplication*.

### Roll back

Remove `dupPort` and `dupDelayMs` from `server.config.json`, `systemctl restart gpn-server`, and optionally
`ufw delete allow 51821/udp`. Clients that have duplication enabled then log that the server has no relay and use
the normal endpoint on their next tunnel start.

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `/api/health` shows `"dup":null` | `dupPort` missing/0 in `server.config.json`, or the service was not restarted |
| Probe echo times out | UDP port blocked by ufw or the provider's cloud firewall, or the port is already used (`ss -lunp`) |
| Log: `EADDRINUSE` / failed to bind | Another process holds that UDP port; pick another `dupPort` |
| Client tunnel never handshakes with duplication on | Wrong/closed relay port, or the proxy resolved an old IP: turn duplication off in the app and relaunch |

## 5. Operations

**Logs & status**

```bash
systemctl status gpn-server
journalctl -u gpn-server -n 100 --no-pager
wg show wg0                                   # peers, handshakes, allowed ips, transfer
```

**Update to a new version**

```bash
# copy the new files over /opt/gpn-server (keep server.config.json), then:
cd /opt/gpn-server && /root/.bun/bin/bun install --production
systemctl restart gpn-server
```

Existing peers survive restarts: they live in WireGuard, and the server re-reads them on start.

**Back up**

```bash
sudo -u postgres pg_dump gpn > gpn-$(date +%F).sql          # users
tar czf gpn-config-$(date +%F).tgz /opt/gpn-server/server.config.json \
  /etc/wireguard/wg0.conf /etc/wireguard/server.key /etc/wireguard/server.pub
# then copy both files off the VPS (they contain secrets: store them encrypted)
```

Redis only holds sessions; losing it just logs everyone out. **Back up `server.key`**: if it changes, every
client's tunnel breaks until it re-registers.

**Rotate the machine token**

Edit `apiToken` in `server.config.json`, then `systemctl restart gpn-server`. Anything using the old token
(headless clients) stops working; user sessions are unaffected.

**Lock out a user**: `POST /api/admin/users/status` with `"inactive"` (see above).

**Lost the only admin password**: there is no reset endpoint. If admin is the only account:

```bash
sudo -u postgres psql gpn -c "DELETE FROM users;"
systemctl restart gpn-server        # recreates 'admin' with a new password in admin-initial-password.txt
```

(With other users present, deleting `admin` alone won't recreate it — promote another user instead:
`sudo -u postgres psql gpn -c "UPDATE users SET role='admin' WHERE username='someone';"`.)

**Change the VPN subnet / interface**: edit `Address` in `wg0.conf` **and** `wgSubnet`/`wgInterface` in the
server config together; existing clients must re-register.

---

## 6. Security notes

- **Close port 9090** to the internet (Step 11) — it is plain HTTP and trusts `X-Forwarded-For`.
- Set an **`inviteCode`** (or firewall the API) unless you want public sign-ups; each account can create tunnels.
- The `apiToken` is a full admin credential; don't paste it into shared places. Clients should prefer user logins.
- `server.config.json`, `server.key` and `admin-initial-password.txt` must stay `chmod 600` and out of git
  (`.gitignore` already excludes the config and the password file).
- Keep Postgres and Redis on loopback; Redis has no password here.
- The clients warn about (the Bun client refuses) plain `http://` server URLs other than localhost, so HTTPS via Caddy is not optional in practice.
- Keep the VPS updated (`unattended-upgrades` is a good idea) and SSH key-only.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `FATAL: apiToken not set` / `db.password … not set` / `publicEndpoint not set` | Missing required config — see Step 7. |
| `password authentication failed for user "gpn"` | `db.password` doesn't match the Postgres user's password (re-run `ALTER USER gpn WITH PASSWORD '…'`). |
| `ECONNREFUSED 127.0.0.1:6379` | Redis isn't running: `systemctl enable --now redis-server`. |
| `ECONNREFUSED 127.0.0.1:5432` | Postgres isn't running: `systemctl status postgresql`. |
| `sudo: wg: command not found` / `wg exited 1` | WireGuard tools not installed, or `wg0` isn't up (`systemctl status wg-quick@wg0`). |
| `ENOENT … /etc/wireguard/server.pub` on `/api/register` | Step 3 key files missing or the server isn't running as root. |
| Clients get HTTP 429 | Per-IP rate limit hit; wait a minute. If *everyone* is limited, `X-Forwarded-For` isn't reaching the server (check the Caddy block), so all clients look like one IP. |
| `peer limit reached (5)` | A user registered too many keys (e.g. reinstalled the client). Raise `maxPeersPerUser`, or remove stale peers with `wg set wg0 peer <KEY> remove && wg-quick save wg0`. |
| Dashboard shows "update server" for the GPN → game leg | The server is older than the latency feature: deploy the new `probe.ts`/`main.ts` and restart. |
| Probes to a game server always show 100% loss | The host drops both ICMP and TCP to that port from the VPS (some game servers firewall everything but the game's own protocol) — the game itself is unaffected. |
| Tunnel connects (handshake OK) but no internet through it | `ip_forward` off, wrong `eth0` in the NAT rules, or ufw forward policy (Step 11). Check `iptables -t nat -S POSTROUTING` and `sysctl net.ipv4.ip_forward`. |
| No handshake at all | UDP 51820 blocked (ufw **and** cloud firewall), wrong `publicEndpoint`, or the client's clock/key is wrong. `tcpdump -ni eth0 udp port 51820` while the client connects. |
| Everyone was logged out after an update | Expected once when moving from the old token format; users sign in again. |
| Caddy can't get a certificate | DNS A record not pointing at the VPS yet, or ports 80/443 closed. |

---

## Known limitations

- **No egress filtering.** The game IPs a client reports are written into its WireGuard `allowed-ips` on the
  server, but WireGuard doesn't use that to restrict where a peer's forwarded traffic may go; any
  authenticated peer can reach any public address through the VPS. A per-peer nftables allow-list is the fix
  if you ever open the service to people you don't trust.
- **Shared game servers collide.** `allowed-ips` is unique per interface, so if two users report the same game
  server IP, the later one takes it from the earlier one in WireGuard's table. Forwarding most likely still
  works for both, since traffic is NAT'd by source address, but this hasn't been tested.
- IPv4 only.
- One VPS, one WireGuard interface, up to ~250 peers (`/24`).

---

## Development

```bash
bun install
# first run writes a default server.config.json — fill in apiToken, publicEndpoint and db.password, then run again
sudo bun run src/main.ts                           # needs sudo for wg commands on a Linux box with wg0
```

The server needs Linux with WireGuard, Postgres and Redis; it can't be exercised end-to-end on Windows.
