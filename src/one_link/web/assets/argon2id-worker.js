"use strict";

// One-shot browser identity KDF worker. The Rust/WASM boundary enforces this
// profile again before allocating the Argon2 matrix; duplicate checks here
// reject hostile envelope parameters before loading or growing WebAssembly.
const ABI_VERSION = 1;
const MEMORY_KIB = 256 * 1024;
const TIME_COST = 3;
const PARALLELISM = 1;
const OUTPUT_LEN = 32;
const SALT_LEN = 16;
const MAX_PASSWORD_BYTES = 1024;
const MAX_WASM_BYTES = 128 * 1024;
const WASM_URL = "/browser-crypto/argon2id-v1.wasm";
const WASM_SHA256 =
  "22aab37746981785f986de39d99cf0e135218899690ce6b359c63e69e5c5d447";

let consumed = false;

function fail(code) {
  const error = new Error("browser identity KDF failed closed");
  error.code = code;
  throw error;
}

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index]);
}

function hex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function allZero(bytes) {
  let aggregate = 0;
  for (const value of bytes) aggregate |= value;
  return aggregate === 0;
}

async function loadModule() {
  const response = await fetch(WASM_URL, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
  });
  if (!response.ok) fail("wasm_http");
  const contentType = (response.headers.get("Content-Type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/wasm") fail("wasm_mime");
  const declaredLength = Number(response.headers.get("Content-Length") || "0");
  if (Number.isFinite(declaredLength) && declaredLength > MAX_WASM_BYTES) {
    fail("wasm_oversize");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 8 || bytes.byteLength > MAX_WASM_BYTES) {
    fail("wasm_size");
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  if (hex(digest) !== WASM_SHA256) fail("wasm_digest");
  const instantiated = await WebAssembly.instantiate(bytes, {});
  const exports = instantiated.instance.exports;
  const requiredFunctions = [
    "ol_argon2id_abi_version",
    "ol_argon2id_alloc",
    "ol_argon2id_free",
    "ol_argon2id_zero",
    "ol_argon2id_derive",
    "ol_argon2id_self_test",
  ];
  if (!(exports.memory instanceof WebAssembly.Memory) ||
      requiredFunctions.some((name) => typeof exports[name] !== "function")) {
    fail("wasm_abi");
  }
  if (exports.ol_argon2id_abi_version() !== ABI_VERSION ||
      exports.ol_argon2id_self_test() !== 0) {
    fail("wasm_self_test");
  }
  return exports;
}

self.onmessage = async (event) => {
  if (consumed) {
    self.postMessage({ ok: false, code: "worker_reused" });
    self.close();
    return;
  }
  consumed = true;
  let password = null;
  let salt = null;
  let exports = null;
  let passwordPtr = 0;
  let saltPtr = 0;
  let outputPtr = 0;
  try {
    const data = event.data;
    if (!exactKeys(data, [
      "abiVersion", "memoryKiB", "parallelism", "password", "salt",
      "timeCost",
    ])) fail("request_schema");
    if (data.abiVersion !== ABI_VERSION || data.memoryKiB !== MEMORY_KIB ||
        data.timeCost !== TIME_COST || data.parallelism !== PARALLELISM) {
      fail("request_profile");
    }
    if (!(data.password instanceof ArrayBuffer) ||
        !(data.salt instanceof ArrayBuffer)) fail("request_buffers");
    password = new Uint8Array(data.password);
    salt = new Uint8Array(data.salt);
    if (password.byteLength < 1 || password.byteLength > MAX_PASSWORD_BYTES ||
        salt.byteLength !== SALT_LEN) fail("request_lengths");

    exports = await loadModule();
    passwordPtr = exports.ol_argon2id_alloc(password.byteLength);
    saltPtr = exports.ol_argon2id_alloc(salt.byteLength);
    outputPtr = exports.ol_argon2id_alloc(OUTPUT_LEN);
    if (!passwordPtr || !saltPtr || !outputPtr) fail("wasm_alloc");
    new Uint8Array(
      exports.memory.buffer, passwordPtr, password.byteLength,
    ).set(password);
    new Uint8Array(exports.memory.buffer, saltPtr, salt.byteLength).set(salt);

    const result = exports.ol_argon2id_derive(
      passwordPtr,
      password.byteLength,
      saltPtr,
      salt.byteLength,
      outputPtr,
      OUTPUT_LEN,
      MEMORY_KIB,
      TIME_COST,
      PARALLELISM,
    );
    if (result !== 0) fail(`wasm_derive_${result}`);
    const passwordAfter = new Uint8Array(
      exports.memory.buffer, passwordPtr, password.byteLength,
    );
    const saltAfter = new Uint8Array(
      exports.memory.buffer, saltPtr, salt.byteLength,
    );
    if (!allZero(passwordAfter) || !allZero(saltAfter)) fail("wasm_zeroization");
    const key = new Uint8Array(OUTPUT_LEN);
    key.set(new Uint8Array(exports.memory.buffer, outputPtr, OUTPUT_LEN));
    exports.ol_argon2id_zero(outputPtr, OUTPUT_LEN);
    self.postMessage(
      {
        ok: true,
        abiVersion: ABI_VERSION,
        key: key.buffer,
        memoryKiB: MEMORY_KIB,
        parallelism: PARALLELISM,
        timeCost: TIME_COST,
      },
      [key.buffer],
    );
  } catch (error) {
    self.postMessage({
      ok: false,
      code: typeof error?.code === "string" ? error.code : "worker_failure",
    });
  } finally {
    if (password) password.fill(0);
    if (salt) salt.fill(0);
    if (exports) {
      try {
        if (passwordPtr) exports.ol_argon2id_free(passwordPtr, password.byteLength);
        if (saltPtr) exports.ol_argon2id_free(saltPtr, salt.byteLength);
        if (outputPtr) exports.ol_argon2id_free(outputPtr, OUTPUT_LEN);
      } catch {}
    }
    setTimeout(() => self.close(), 0);
  }
};
