# One Link rendezvous — operator quickstart

A small server. Doesn't see your messages. Lets paired devices find
each other across the internet.

## 30-second deploy

```bash
cd deploy/rendezvous
docker compose up -d
curl -sS http://localhost:7118/health
# {"ok": true, ...}
```

That gives you a rendezvous on port 7118 of your box. To make it
reachable from the public internet, see the **TLS** section below or
the full [`docs/RENDEZVOUS_DEPLOY.md`](../../docs/RENDEZVOUS_DEPLOY.md).

## Files

- `Dockerfile` — two-stage build, minimal runtime, non-root user.
- `entrypoint.sh` — env → flags shim.
- `docker-compose.yml` — production-shape compose with hardening.
- `nginx.conf.example` — drop-in TLS termination via Let's Encrypt.

## Telling your One Link clients to use it

In the One Link app: **Settings → Connect across networks** → paste
the URL (with `https://` prefix once TLS is set up). The status dot
turns green and shows the public IP your clients announce to each
other.

You can run multiple rendezvous instances and your clients will
register with all of them in parallel for redundancy.

## TLS

Always front this with HTTPS. The rendezvous protocol is signed
end-to-end so a compromised TLS hop can't read or forge content, but
TLS prevents passive observers from seeing which pubkeys look up
which.

Easiest path:

```bash
sudo cp nginx.conf.example /etc/nginx/sites-available/one-link-rendezvous.conf
# edit server_name to your domain
sudo ln -s ../sites-available/one-link-rendezvous.conf /etc/nginx/sites-enabled/
sudo certbot --nginx -d rendezvous.your-domain.example
sudo systemctl reload nginx
```

Cloudflare alternative: point an A record at your VPS, enable orange-
cloud (proxy on), set SSL/TLS mode to **Full (strict)**.

## Monitoring

```bash
curl -sS http://localhost:7118/metrics
```

Returns plain JSON keys — easy to relabel into Prometheus.

## Resource shape

- ~1 KB process memory per active registration.
- Default cap: 200,000 registrations (~200 MB peak).
- CPU: idle. Bandwidth: tens of KB/s.
- A $5/month VPS is overkill for any reasonable user base.

## Reading the logs

The default INFO log line shows registers / lookups / rate-limit hits.
At DEBUG you also see eviction counts and per-request signature
verifies. Set `ONE_LINK_RDZ_LOG_LEVEL=DEBUG` in the compose file to
turn those on.

## Restart-safe

The rendezvous holds presence in memory only. A restart loses all
current registrations — devices re-register within minutes (every
TTL/2, default 150 s). No persistent data lives in this container,
so the `read_only: true` filesystem in compose is correct.

## Federation

There's no protocol-level state sync between rendezvous instances.
Federation is a client-side concept: clients register with multiple
rendezvous in parallel and lookups race them. Run yours, and tell
your friends to add it alongside whatever they're already using.

## Compliance / metadata

This rendezvous sees only signed presence beacons:
`(pubkey, source_IP, advertised_endpoints)`. No payloads, no group
membership, no messages. If you operate one publicly, your privacy
posture should reflect that you're holding **online-status metadata
of pubkey-keyed devices** — not contents.
