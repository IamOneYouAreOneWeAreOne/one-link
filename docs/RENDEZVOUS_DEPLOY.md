# Operating a One Link Rendezvous

A One Link rendezvous is a small server that lets paired devices on
different networks find each other. It carries no plaintext payload —
only signed presence beacons — and it can be run by anyone, anywhere.

> **TL;DR for impatient operators:**
> ```
> docker run -d --name one-link-rendezvous --restart unless-stopped \
>     -p 7118:7118 onelink/rendezvous:latest
> ```
> Then put `https://your-host` (after fronting it with TLS) into the
> "Connect across networks" field in One Link's Settings. Done.

---

## What it does, what it doesn't

**Does:**
- Holds, in memory, a small signed record per pubkey:
  `(pubkey, observed_public_IP, advertised_endpoints[], capabilities)`.
- Replies to lookups: "where is `pubkey X`?"
- Bounded resources: hard cap on registrations (default 200k),
  per-IP rate limit, per-pubkey register rate limit.
- Periodically evicts expired entries.
- All registers and revokes are Ed25519-signed by the device. The
  rendezvous can't impersonate anyone because it doesn't hold private
  keys.

**Does NOT:**
- See chat messages, file contents, or any payload bytes. End-to-end
  encryption stays between the paired devices.
- Persist anything to disk. A restart loses all current presence
  registrations — devices re-register within a few minutes.
- Authenticate operators or users. The protocol is symmetric. Trust
  comes from the cryptographic signatures, not the operator.

**Threat model summary:**
- A malicious or compromised rendezvous can:
  - Drop or refuse to forward presence (DoS — users notice immediately)
  - Lie about who is registered (clients verify nothing about lookup
    responses except shape; bad data just causes failed dial attempts)
  - Observe public-IP-of-pubkey metadata — *who is online when, from
    where*. v0.5.3 sealed-sender will hide this.
- A malicious or compromised rendezvous **cannot**:
  - Read plaintext (impossible — it doesn't carry payload)
  - Impersonate a device (no private keys)
  - Forge registrations under someone else's pubkey (signature check)
  - Replay old registrations to confuse clients (60s replay window)

---

## Hardware requirements

The rendezvous is intentionally small. For up to about 200,000
simultaneous registrations:

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 256 MB | 512 MB |
| CPU | 1 vCPU | 1 vCPU |
| Disk | 100 MB (binaries + logs) | 1 GB |
| Bandwidth | tens of KB/s | 1 Mbps burst |

A `$5/month` VPS handles this without strain. If you outgrow one
instance, run more — devices can register with multiple in parallel
and lookups race them.

---

## Deployment

### Option 1 — Docker (recommended)

`docker-compose.yml` ships in the repo at `deploy/rendezvous/`:

```yaml
services:
  rendezvous:
    image: onelink/rendezvous:0.5.3
    restart: unless-stopped
    ports:
      - "7118:7118"
    environment:
      ONE_LINK_RDZ_HOST: "0.0.0.0"
      ONE_LINK_RDZ_PORT: "7118"
      ONE_LINK_RDZ_LOG_LEVEL: "INFO"
```

Run:

```bash
cd deploy/rendezvous
docker compose up -d
```

Logs:

```bash
docker compose logs -f rendezvous
```

### Option 2 — systemd

```ini
# /etc/systemd/system/one-link-rendezvous.service
[Unit]
Description=One Link rendezvous
After=network.target

[Service]
Type=simple
User=onelink
Group=onelink
ExecStart=/usr/bin/python3 -m one_link.rendezvous_server \
    --host 0.0.0.0 --port 7118
Restart=always
RestartSec=2
# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin onelink
sudo pip3 install one_link
sudo systemctl daemon-reload
sudo systemctl enable --now one-link-rendezvous
```

### Option 3 — bare metal

```bash
pip install one_link
python -m one_link.rendezvous_server --host 0.0.0.0 --port 7118
```

Use a process manager (supervisord, runit, pm2, …) to keep it up.

---

## TLS

**Always front the rendezvous with HTTPS.** The protocol is
end-to-end signed, so a compromised TLS hop can't read or forge
content — but TLS prevents passive observers on the LAN from learning
which pubkeys are looking up which.

### nginx + Let's Encrypt

```nginx
# /etc/nginx/sites-available/rendezvous.example.com
server {
    listen 443 ssl http2;
    server_name rendezvous.example.com;

    ssl_certificate     /etc/letsencrypt/live/rendezvous.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rendezvous.example.com/privkey.pem;

    # Reasonable defaults, drop legacy.
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Don't buffer — payloads are tiny.
    proxy_buffering off;
    client_max_body_size 16k;

    location / {
        proxy_pass http://127.0.0.1:7118;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 30s;
    }

    # Optional: ban path-traversal nonsense at the edge.
    location ~ \.\. { return 400; }
}

server {
    listen 80;
    server_name rendezvous.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo certbot --nginx -d rendezvous.example.com
```

### Cloudflare (alternative)

Point a DNS A record at your VPS, enable "Proxy" (orange cloud).
Cloudflare terminates TLS on its edge, hits your origin on port 80
or 7118 directly. Set the SSL/TLS mode to **Full (strict)** if you
also have a cert on the origin (recommended).

The rendezvous reads `X-Forwarded-For` so client IP is preserved
through the proxy chain.

---

## Verifying the deployment

### Health check

```bash
curl -sS https://rendezvous.example.com/health
# {"ok": true, "uptime_ms": 12345, "registrations": 0}
```

### Metrics

```bash
curl -sS https://rendezvous.example.com/metrics
# {
#   "registers_total": 1234,
#   "lookups_total": 5678,
#   "lookup_misses_total": 12,
#   "rate_limit_rejects_total": 0,
#   ...
# }
```

Hook into Prometheus / Grafana / your monitoring of choice — the
endpoint returns plain JSON keys so `prometheus-jmx-exporter`-style
relabeling is trivial.

### From a One Link client

In the One Link UI: **Settings → Connect across networks**, paste:

```
https://rendezvous.example.com
```

The status dot turns green and the panel shows your observed public
IP. If you're behind NAT, this is the IP your devices announce to
each other.

---

## Tuning for scale

Defaults handle ~200,000 simultaneous registrations on commodity
hardware. To go higher:

```bash
python -m one_link.rendezvous_server \
    --host 0.0.0.0 \
    --port 7118 \
    --max-registrations 1000000 \
    --rate-per-ip-per-min 600 \
    --rate-register-per-pubkey-per-min 60
```

Each registration is roughly 1 KB of process memory. 1M = ~1 GB.

For higher throughput than one process can handle, run multiple
behind a load-balancer with `ip_hash` or `consistent_hash` so the
same client IP lands on the same instance (rate-limiter is per-IP
per-instance — sticky routing keeps it accurate).

---

## Federation

Devices can register with multiple rendezvous in parallel, and
lookups race all configured rendezvous, returning the first hit. To
provide redundancy:

1. Run two or more rendezvous instances at independent operators.
2. Have your users add both URLs to **Settings → Connect across
   networks** (one per line).
3. Both will receive registrations; either can satisfy lookups.

There is no protocol-level sync between instances — by design.
Eventual consistency happens through clients re-registering on
their refresh schedule (every TTL/2, default 150 s).

---

## Privacy posture

The rendezvous learns:
- Which pubkeys are online and their public IPs (the metadata that
  TLS hides from network observers but the rendezvous itself sees).
- Which pubkeys looked up which other pubkeys (only IF the looking
  pubkey was identifiable; v0.5.0 lookups are anonymous — no auth).
- Approximate device geo from IP (whatever IP geolocation lookup
  reveals).

The rendezvous does NOT learn:
- Anything about message content
- Anything about file content
- Group membership (groups are an end-to-end primitive on top of the
  rendezvous, not a rendezvous-side feature)

To minimize what the rendezvous sees:
- Put it behind Tor (run an onion service in front of it; the One
  Link client supports `https?://` URLs only in v0.5.3, but a SOCKS
  proxy in front of `aiohttp` is a small client patch).
- Self-host. Operating your own rendezvous means you trust nobody
  outside your house with this metadata.

---

## Incident response

If your rendezvous gets compromised:

1. **Rotate the host.** Bring up a new one at a different IP / domain.
2. **Tell your users to update their rendezvous URL.** They need a
   trusted out-of-band channel for this — exactly the same channel
   they use to bootstrap pairing.
3. **Don't worry about message confidentiality.** A compromised
   rendezvous can't decrypt anything. The cost of compromise is
   metadata + uptime.

A compromised rendezvous can't impersonate any client because it
doesn't hold private keys. The damage is bounded to: knowing who's
online, and (if the rendezvous lies on lookup) directing dials at
the wrong public IP — which fail closed because the One Link channel
verifies the peer's pubkey at handshake.

---

## Why does this exist?

Most modern messaging apps need a centralized rendezvous service
operated by the app vendor — Signal, WhatsApp, iMessage — and you
have to trust that vendor's metadata posture. One Link's rendezvous
is the same architectural primitive but the operator can be:

- The user's home server.
- A friend's machine.
- A community-run instance.
- A commercial provider you choose.
- Any combination of the above.

There is no "official" rendezvous you must use. The protocol is
public, the binary is small, the operating cost is rounding-error
small, and the trust surface is metadata-only. We expect a healthy
ecosystem of small operators rather than one giant.
