#!/bin/sh
# Map the small set of ONE_LINK_RDZ_* env vars onto rendezvous_server flags.
# Operators who prefer flags can pass them as `docker run` arguments and
# this wrapper passes them through after the env-derived ones (later
# argparse occurrences win).
set -eu

exec python -m one_link.rendezvous_server \
    --host "${ONE_LINK_RDZ_HOST:-0.0.0.0}" \
    --port "${ONE_LINK_RDZ_PORT:-7118}" \
    --max-registrations "${ONE_LINK_RDZ_MAX_REGISTRATIONS:-200000}" \
    --rate-per-ip-per-min "${ONE_LINK_RDZ_RATE_PER_IP_PER_MIN:-120}" \
    --rate-register-per-pubkey-per-min "${ONE_LINK_RDZ_RATE_REGISTER_PER_PUBKEY_PER_MIN:-30}" \
    --log-level "${ONE_LINK_RDZ_LOG_LEVEL:-INFO}" \
    "$@"
