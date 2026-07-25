# One Link rendezvous — operator quickstart

A small server. Doesn't see your message contents. Lets paired devices find
each other across the internet.

## Build and run from reviewed source

```bash
# First check out the exact full commit SHA you reviewed.
cd deploy/rendezvous
ONE_LINK_VCS_REF="$(git rev-parse HEAD)" docker compose up -d --build
curl -sS http://localhost:7118/health
# {"ok": true}
```

There is currently no verified public One Link container image. The compose
file intentionally builds the checked-out source and does not name a registry
image. It publishes plain HTTP only on `127.0.0.1:7118`; put the TLS reverse
proxy below in front of that loopback socket before making it public. See the
full [`docs/RENDEZVOUS_DEPLOY.md`](../../docs/RENDEZVOUS_DEPLOY.md).

## Files

- `Dockerfile` — digest-pinned multi-stage build, minimal runtime, non-root user.
- `requirements.in` / `requirements.lock` — rendezvous-only dependency input
  and exact, hash-locked wheel closure.
- `entrypoint.sh` — env → flags shim.
- `docker-compose.yml` — hardened local-source deployment baseline.
- `nginx.conf.example` — drop-in TLS termination via Let's Encrypt.

## Supply-chain properties and limits

- The CPython and uv images are pinned by immutable OCI index digests.
- Python packages are exact-version and SHA-256 locked; source distributions
  are refused during the image build.
- The final image has no package installer/build tool and includes only the
  six One Link modules in the rendezvous import closure.
- `.dockerignore` deny-lists the entire repository first, preventing `.git`,
  identities, local databases, test captures, and build artifacts from being
  sent to the builder.

These controls make inputs reviewable and fail closed on drift. They do not by
themselves prove byte-identical image reproduction or constitute a signed
release. Record `ONE_LINK_VCS_REF`, retain the resulting image digest/SBOM, and
apply your registry signing policy before distributing an image.

## Telling your One Link clients to use it

In the One Link app: **Settings → Connect across networks** → paste
the URL (with `https://` prefix once TLS is set up). The status dot
turns green and shows the public IP your clients announce to each
other.

You can run multiple rendezvous instances and your clients will
register with all of them in parallel for redundancy.

## TLS

Always front this with HTTPS. Device registration/revocation authenticity is
signature-checked, while TLS protects request and presence metadata from
passive network observers. A compromised rendezvous or TLS endpoint can still
observe metadata, drop requests, replay within accepted windows, or redirect
dial attempts; the peer channel separately authenticates the paired peer.

The compose baseline sets `ONE_LINK_RDZ_TRUST_PROXY_HEADERS=true` because its
only published socket is host-loopback and nginx is the intended direct peer.
Host-local processes can also reach that socket, so this topology treats the
host as one security domain; use a dedicated host/VM or firewall/namespace
controls on a multi-tenant machine. If you publish port 7118 directly, set that
value to `false` so clients cannot forge rate-limit identities through
`X-Forwarded-For`. The nginx baseline overwrites that header, strips the
untrusted standardized `Forwarded` variant and cookies, and hides upstream
cookie/runtime headers. Bounded nginx request/connection zones shed per-source
floods before they allocate backend Python handlers; application quotas remain
the stricter protocol-aware boundary.

Use Docker Engine 28.3.3 or newer. Older than 28.0.0 could expose localhost-
published ports to the same L2 network, and 28.3.3 fixed a firewalld-reload
regression with the same consequence. See Docker's
[port-publishing warning](https://docs.docker.com/engine/network/port-publishing/)
and [28.3.3 security note](https://docs.docker.com/engine/release-notes/28/#2833).

Easiest path:

```bash
# The vhost references final certificate paths. Obtain them before enabling it;
# standalone requires port 80 to be free.
sudo certbot certonly --standalone -d rendezvous.your-domain.example
sudo cp nginx.conf.example /etc/nginx/sites-available/one-link-rendezvous.conf
# replace every rendezvous.example.com with your domain
sudo ln -s ../sites-available/one-link-rendezvous.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

The standalone command above is for initial issuance while port 80 is free; it
is not a complete unattended-renewal setup once nginx is running. Configure a
DNS/webroot renewal flow or explicit safe service hooks for your environment,
then require `certbot renew --dry-run` to pass before calling the deployment
production-ready.

Cloudflare DNS-only records work with this nginx baseline. Do **not** simply
enable orange-cloud proxying: nginx would otherwise see a Cloudflare edge IP,
collapsing client rate limits and publishing the wrong observed address. If you
need Cloudflare proxying, first configure nginx's real-IP module from
Cloudflare's maintained IP ranges, restrict the origin to those ranges, and
only then forward `$remote_addr`; require **Full (strict)** origin TLS, never
Flexible mode. Follow Cloudflare's [original visitor IP
guidance](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/).

Browser peers can call the signed register/revoke and public lookup routes
cross-origin. The backend answers narrowly validated, credential-free CORS
preflights for only those routes. `/metrics` never receives CORS permission,
and relay WebSocket handshakes reject every browser `Origin`; native relay
clients authenticate through the signed relay protocol and omit `Origin`.

## Monitoring

The shipped nginx vhost returns 404 for public `/metrics`. Configure a
high-entropy backend token as a mounted secret for local monitoring (never put
the token in a URL or compose environment value):

```bash
install -d -m 700 ./secrets
openssl rand -hex 32 > ./secrets/metrics-token
chmod 600 ./secrets/metrics-token

cat > compose.metrics.yml <<'YAML'
services:
  rendezvous:
    environment:
      ONE_LINK_RDZ_METRICS_TOKEN_FILE: /run/secrets/one-link-metrics-token
    secrets:
      - one-link-metrics-token
secrets:
  one-link-metrics-token:
    file: ./secrets/metrics-token
YAML
docker compose -f docker-compose.yml -f compose.metrics.yml up -d

TOKEN="$(cat ./secrets/metrics-token)"
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  http://localhost:7118/metrics
unset TOKEN
```

Returns JSON metrics. This is not Prometheus exposition format; use an adapter
or JSON-aware collector. If you deliberately remove nginx's exact `/metrics`
deny, the backend still requires this token for every effective non-loopback
client. With trusted proxy headers enabled, missing or malformed forwarding
identity fails closed and also requires the token.

## Resource shape

- The shipped 512 MiB profile caps registrations and every attacker-keyed
  rate/nonce/replay map at 20,000 keys, concurrent handlers at 64, and the
  pairwise relay routing table at 4,096 rotating tags; the optional relay
  payload budget is 128 MiB. It declares the same 512 MiB to the
  server, which refuses startup if those configured ceilings no longer fit.
  The handler reserve includes one maximum relay frame because aiohttp must
  parse that frame before application-level relay budget admission can run.
- Compose caps the process at 1 CPU, 512 MiB RAM, 128 PIDs, and 65,536 open
  files. Its 120-second stop grace covers the relay's bounded ordered teardown
  path before Docker escalates to a forced kill. An adversarial state probe at
  the old 50,000-key shape increased RSS by 433,811,456 bytes before relay
  payloads or meaningful connection load; that is why the previous
  200,000/512 MiB contract was removed.
- These are memory-safety defaults, not a throughput SLO. Raise any state cap
  only together with a measured hostile-state RSS run, container memory, and
  relay/concurrency budgets; lowering one cap does not compensate for silently
  leaving the other attacker-controlled maps unbounded.
- Abuse quotas preserve individual IPv4 identities and aggregate native IPv6
  addresses by /64, preventing interface-address rotation from resetting every
  per-IP bucket. A full limiter map rejects unknown identities until inactive
  buckets expire instead of evicting and resetting a live client's quota. Full
  IPv6 addresses remain available as observed endpoints.

## Reading the logs

The nginx baseline disables access logs on both the HTTP redirect and TLS
vhosts because request paths contain pubkeys, blinded tokens, and relay
destinations. It also restricts the non-redactable nginx error log to emergency
process events. The application disables aiohttp's raw-target access logger and
logs bounded event summaries; rate-limit events use route templates rather than
concrete paths. DEBUG can include raw client IPs, so enable it only under an
explicit retention policy.

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

This rendezvous sees signed presence beacons:
`(pubkey, source_IP, advertised_endpoints)`. When encrypted relay is enabled,
it also forwards opaque ciphertext and observes socket addresses, sizes,
timing, and rotating route-tag activity; it does not receive plaintext or
end-to-end keys. Production v2 relay paths use pairwise tags, and its
identity-bearing channel HELLO/REPLY flights are sealed before forwarding, so
neither endpoint identity public key appears in relay DATA or routing control.
The explicit legacy v1 migration route exposes the destination public key and
raw channel identities. Rotation does not prevent the same relay correlating
tags through a persistent listener socket and refresh sets, and route-set
cardinality reveals an approximate paired-peer count. Because this service also
handles signed presence, its operator can attempt IP/timing correlation between
relay sockets and presence identities. It does not learn group membership from
the relay protocol itself.
If you operate one publicly, your privacy posture should reflect that you're
holding **online-status and traffic metadata** — not plaintext contents or an
anonymity guarantee.
