"""Executable browser proof for One Setup's independently derived SAS.

The phone must not merely echo a phrase supplied by the daemon.  This test
extracts and executes the JavaScript shipped in ``peer.html`` and checks it
against the Python authority, including key/secret binding and fail-closed
response validation.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

import pytest

from one_link.pairing import compute_setup_sas_words, format_sas_words


PEER_HTML = Path("src/one_link/web/peer.html")
NODE = shutil.which("node")


def _section(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    return source[start_index:source.index(end, start_index)]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _run_node(script: str) -> str:
    if NODE is None:
        pytest.skip("Node is required for executable browser SAS proofs")
    result = subprocess.run(  # noqa: S603 - fixed local executable, no shell
        [NODE, "--input-type=commonjs"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"Node proof failed ({result.returncode})\nstdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    return result.stdout.strip()


def test_setup_sas_browser_python_parity_and_fail_closed() -> None:
    source = PEER_HTML.read_text(encoding="utf-8")
    constants = _section(
        source,
        "const PAIR_SAS_WORDS = Object.freeze([",
        "// OPFS peers store.",
    )
    canonical_b64 = _section(
        source,
        "function _canonicalB64UrlBytes",
        "function _canonicalSha256Fingerprint",
    )
    digest_words = _section(
        source,
        "function _sasWordsFromDigest",
        "async function _computeSas",
    )
    setup_helpers = _section(
        source,
        "function _compareByteArrays",
        "async function _runSetupDeviceInviteFlow",
    )

    owner = bytes(range(32))
    device = bytes(range(32, 64))
    secret = bytes(range(64, 96))
    expected = format_sas_words(
        compute_setup_sas_words(owner, device, invite_secret=secret)
    )

    script = f"""
const assert = require("node:assert/strict");
const {{ webcrypto }} = require("node:crypto");
Object.defineProperty(globalThis, "crypto", {{ value: webcrypto }});
function bytesToB64Url(value) {{
  return Buffer.from(value).toString("base64url");
}}
function b64UrlToBytes(value) {{
  return new Uint8Array(Buffer.from(value, "base64url"));
}}
function _requirePlainObject(value, label) {{
  if (!value || typeof value !== "object" || Array.isArray(value)) {{
    throw new Error(`${{label}} must be a plain object`);
  }}
  return value;
}}
{constants}
{canonical_b64}
{digest_words}
{setup_helpers}

(async () => {{
  const owner = "{_b64u(owner)}";
  const device = "{_b64u(device)}";
  const token = "{_b64u(secret)}";
  const expected = "{expected}";
  const forward = await _deriveSetupSas(token, owner, device);
  const reverse = await _deriveSetupSas(token, device, owner);
  assert.equal(forward.phrase, expected);
  assert.equal(reverse.phrase, expected);
  assert.deepEqual(reverse.words, forward.words);

  const changedSecret = new Uint8Array(Buffer.from(token, "base64url"));
  changedSecret[31] ^= 1;
  const changed = await _deriveSetupSas(
    bytesToB64Url(changedSecret), owner, device,
  );
  assert.notEqual(changed.phrase, expected);
  await assert.rejects(() => _deriveSetupSas("short", owner, device));

  const identity = {{ public_key_b64u: device }};
  const body = {{
    sas_version: SETUP_SAS_VERSION,
    root_pub_b64: owner,
    device_pub_b64: device,
    trust_phrase: expected,
    trust_code: expected,
    trust_words: forward.words,
  }};
  assert.equal(
    (await _validateSetupClaim({{ token }}, identity, body)).phrase,
    expected,
  );
  await assert.rejects(() => _validateSetupClaim(
    {{ token }}, identity, {{ ...body, trust_phrase: "agile amuse apple basil blaze" }},
  ));
  await assert.rejects(() => _validateSetupClaim(
    {{ token }}, identity, {{ ...body, sas_version: "digits-v2" }},
  ));
  await assert.rejects(() => _validateSetupClaim(
    {{ token }}, {{ public_key_b64u: owner }}, body,
  ));
  process.stdout.write("setup-sas-ok");
}})().catch((error) => {{
  console.error(error);
  process.exitCode = 1;
}});
"""
    assert _run_node(script) == "setup-sas-ok"
