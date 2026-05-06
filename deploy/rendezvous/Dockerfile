# One Link rendezvous container.
#
# Stage 1: build a wheel from the repo (so the runtime image only ships
# the package, no toolchain).
# Stage 2: minimal runtime, non-root user, single ENTRYPOINT.

# ─── stage 1: build ──────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS build

WORKDIR /src

# System build deps for cryptography wheels (kept thin — slim base lacks gcc).
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Copy only what's needed for `pip install .`.
COPY pyproject.toml README.md LICENSE NOTICE /src/
COPY src /src/src

RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /wheels


# ─── stage 2: runtime ────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

# Non-root user; nothing about the rendezvous needs root.
RUN useradd --system --create-home --shell /usr/sbin/nologin onelink

WORKDIR /home/onelink

# Install just the wheel — drops 200MB of build toolchain.
COPY --from=build /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
 && rm -f /tmp/*.whl

USER onelink

# Sane defaults; override via -e or compose env.
ENV ONE_LINK_RDZ_HOST=0.0.0.0 \
    ONE_LINK_RDZ_PORT=7118 \
    ONE_LINK_RDZ_LOG_LEVEL=INFO \
    ONE_LINK_RDZ_MAX_REGISTRATIONS=200000 \
    ONE_LINK_RDZ_RATE_PER_IP_PER_MIN=120 \
    ONE_LINK_RDZ_RATE_REGISTER_PER_PUBKEY_PER_MIN=30

EXPOSE 7118/tcp

# Tiny shell wrapper to plumb env vars into argparse flags.
COPY --chown=onelink:onelink entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Healthcheck — uses the /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; \
        r = urllib.request.urlopen('http://127.0.0.1:7118/health', timeout=2); \
        sys.exit(0 if r.status == 200 else 1)" || exit 1
