# Testing One_link

## Run the full suite

```bash
pip install -e .[dev]
python -m pytest tests/ --ignore=tests/smoke_loopback.py -v
```

Expect ~94 tests, ~90 seconds. The integration tests spin real daemons in
subprocesses and use mDNS, which is the slow part.

## Test layout

| File | What it covers | Network |
|---|---|---|
| `tests/test_identity.py` | Ed25519 keypair gen, fingerprint, persistence, sign/verify, tampered/garbage rejection | none |
| `tests/test_wire.py` | Length-prefixed framing round-trip, oversize attack, truncation, unicode envelope encoding | none |
| `tests/test_paths.py` | Cross-platform config/data dirs, `ONE_LINK_HOME` override | none |
| `tests/test_channel.py` | X25519 handshake (initiator + responder), AEAD send/recv, large payloads, bad signatures, tampered ciphertext, fresh ephemeral keys per session | TCP loopback |
| `tests/test_discovery.py` | Peer registry: upsert, find by id / hostname / prefix, remove, on_change callback | none |
| `tests/test_cli.py` | `one-link` CLI as subprocess: --version, --help, whoami persistence, friendly errors when daemon missing, full send/send-file round-trips | subprocess + mDNS |
| `tests/test_integration.py` | Two-daemon end-to-end: TEXT, send-by-hostname, send-by-prefix, file matrix (0 / 1 / 255 / 256K-1 / 256K / 256K+1 / 512K / 5MB), unicode filenames, malformed control requests, concurrency (10 parallel sends) | mDNS |
| `tests/test_raw_protocol.py` | Hand-crafted attacker traffic: path traversal across 7 vectors, oversize frame header, garbage handshake, truncated handshake | mDNS + raw TCP |
| `tests/test_resilience.py` | Stale port files, garbage on peer port (×20), burst connect/disconnect (×50), two daemons same home, peer disconnect mid-frame | subprocess + mDNS |
| `tests/test_tail.py` | Live event subscription, multiple subscribers, subscriber disconnect doesn't break others | mDNS |

## What gets verified

### Security
- Path traversal blocked: `../../etc/passwd`, `..\\..\\Windows\\System32\\evil.dll`, `/etc/passwd`, `C:\\Windows\\System32\\evil.dll`, `subdir/inner.txt`, `..`, `.` — all land in inbox/, never escape.
- Frame oversize attack rejected before allocation.
- Garbage handshake rejected, daemon stays up.
- Tampered ciphertext fails AEAD, channel closes.
- Bad Ed25519 signature in handshake → reject.
- Each new connection uses fresh X25519 ephemerals (no key reuse).
- Outbound sends verify the responder's fingerprint matches the expected peer.

### Correctness
- File transfer is byte-identical for: 0, 1, 255, 256K-1, 256K, 256K+1, 512K, 5MB.
- Unicode filenames round-trip on both Win and Mac filesystems.
- Concurrent sends from one daemon all land without corruption.
- Message log captures both directions.

### Resilience
- Stale `control.port`/`peer.port` from previous run don't break startup.
- Daemon survives 20 garbage payloads on the peer port.
- Daemon survives 50 abrupt connect/disconnect cycles.
- Two daemons with the same `ONE_LINK_HOME` → no crash (race-tolerant, last-write wins).
- Peer disconnect mid-frame doesn't break the server.
- CLI gives a friendly error when the daemon isn't running (no traceback).

## Known limitations / what's NOT tested

- **Internet P2P** — we only run on loopback / LAN. Real NAT-traversal scenarios
  aren't exercised yet.
- **Long-running soak** — no multi-hour stability test. File-descriptor leaks
  over weeks aren't covered.
- **Cross-version compat** — we don't test "old daemon talks to new daemon".
  The protocol header is `OL1`; we'll bump it for breaking changes.
- **Memory pressure / OOM** — no test for "send many GB simultaneously".
- **Filesystem race** — what if two peers send the same file at the same
  time, with the same blob hash? Currently the second offer reopens the same
  inbox path; not currently tested.

## Smoke test (legacy)

`tests/smoke_loopback.py` is a standalone script (not a pytest test) that
exercises the same end-to-end path. It pre-dates the pytest suite and is kept
as a quick manual sanity check:

```bash
python tests/smoke_loopback.py
```

## CI

GitHub Actions matrix (`.github/workflows/tests.yml`):
- Windows + macOS, Python 3.11 + 3.12
- Unit tests must pass; integration tests run with `continue-on-error` because
  mDNS reliability on hosted runners is hit-or-miss.
- On push to `master`, builds Windows + macOS binaries and uploads them as
  workflow artifacts.
