# ADR-0008: Python ↔ Rust FFI Contract

**Status:** ACCEPTED (Phase A1 acceptance number)
**Phase:** A1 (foundation for all Rust crates: ol_chunk, ol_chunk_store, ol_aead, etc.)
**Depends on:** nothing

---

## Context

Per FILE_ENGINE_V2_PLAN.md (corrected runtime decision): hot-path code goes to Rust; orchestration stays Python. The existing One Link daemon (`src/one_link/server.py`, `daemon.py`, `peer_rtc.py`, etc.) imports Rust crates the same way it currently imports the C extension. The FFI boundary must:

1. Not be a hot-path bottleneck. Per-byte calls are forbidden; per-chunk calls are acceptable; per-batch calls are preferred.
2. Be safe. No Python crashing the Rust daemon, no Rust UB crashing Python.
3. Be installable like any Python package. `pip install one-link-native` (eventually) or `pip install -e .` for dev.
4. Cross-platform: Linux, macOS (x86 + ARM), Windows.
5. Allow zero-copy buffer passing where it matters (chunk content, not metadata).

## Decision

**Use `pyo3` for Rust↔Python bindings, packaged via `maturin`. Mixed PyO3 + native libraries (`libc`, OS-specific I/O) for hot-path crates that touch the OS directly.**

Specifically:

- **`pyo3 = "0.29"`** for Python bindings on each Rust crate that needs Python-callable surface. This is the workspace security floor; older 0.22.x releases are affected by RustSec advisories for an out-of-bounds string read and a missing `Sync` bound on Python-callable closures.
- **`maturin = ">=1.5"`** for build-and-package. Replaces `setuptools` for the native portion.
- **`pyproject.toml`** in `One_link/native/` declares maturin as build backend for the native package.
- **`abi3` mode** (stable Python ABI, Python 3.11+) so a single wheel works across supported Python versions.
- **Interpreter detached around long-running ops** via `py.detach(|| ...)` so Python concurrency isn't blocked by Rust work.
- **Zero-copy buffer passing** via `pyo3::buffer::PyBuffer` for byte arrays. Rust receives a `&[u8]` directly into Python's bytes/bytearray/memoryview, no copy.
- **Error model**: Rust errors (`anyhow::Error` / custom `OlError`) map to Python exceptions via `PyErr` derivation. Each crate defines its own `PyErr` subclass: `OlChunkError`, `OlStoreError`, `OlAeadError`, etc. All inherit from a base `OlError(Exception)` for catch-all handling.

### Workspace layout:

```
One_link/native/
├── Cargo.toml                      # Workspace root; lists all member crates
├── pyproject.toml                  # maturin build backend declaration
├── README.md                       # Workspace-level docs
├── ol_chunk/                       # Phase A1: CDC + BLAKE3 (FIRST CRATE)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                  # Pure Rust API + #[pyfunction] wrappers
│       ├── cdc.rs                  # FastCDC kernel (scalar + AVX-512 + NEON dispatch)
│       ├── blake3_wrap.rs          # BLAKE3 derive_key wrappers per ADR-0006
│       └── frame.rs                # AEAD frame layout per ADR-0002
├── ol_chunk_store/                 # Phase A1: LSM + bloom + chunk_log + manifest_log
├── ol_wal/                         # Phase A1: crash-only WAL (per ADR-0007)
├── ol_aead/                        # Phase A1: per-chunk AEAD pipeline
└── ... (B / C / D crates added as those phases ship)
```

### Pyo3 binding pattern (canonical):

```rust
// ol_chunk/src/lib.rs

use pyo3::prelude::*;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;

mod cdc;
mod blake3_wrap;

#[pyclass]
pub struct ChunkBoundaryIterator {
    inner: std::vec::IntoIter<cdc::Boundary>,
}

#[pymethods]
impl ChunkBoundaryIterator {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> { slf }
    fn __next__(mut slf: PyRefMut<Self>) -> Option<(usize, usize, Vec<u8>)> {
        slf.inner.next().map(|b| (b.start, b.end, b.raw_address.to_vec()))
    }
}

/// Iterate CDC chunk boundaries over a buffer. Returns iterator yielding (start, end, BLAKE3-32-bytes).
/// Releases GIL for the duration of the scan.
#[pyfunction]
pub fn cdc_iter(py: Python<'_>, buf: PyBuffer<u8>) -> PyResult<ChunkBoundaryIterator> {
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err("buffer must be C-contiguous"));
    }
    let len = buf.item_count();
    // SAFETY: PyBuffer owns the exported buffer view until this function
    // returns. Detaching the interpreter does not release that view, and the
    // scan returns owned boundaries before `buf` can drop.
    let bytes = if len == 0 {
        &[]
    } else {
        // SAFETY: `len > 0`, so a successful PyBuffer export supplies a
        // non-null, correctly aligned pointer valid for `len` bytes.
        unsafe { std::slice::from_raw_parts(buf.buf_ptr().cast::<u8>(), len) }
    };
    let boundaries = py.detach(|| cdc::scan_to_vec_parallel(bytes));
    Ok(ChunkBoundaryIterator { inner: boundaries.into_iter() })
}

#[pymodule]
fn ol_chunk(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ChunkBoundaryIterator>()?;
    m.add_function(wrap_pyfunction!(cdc_iter, m)?)?;
    Ok(())
}
```

### Buffer-lifetime safety contract:

The `PyBuffer<u8>` API guarantees:

- Python holds a reference to the underlying `bytes`/`bytearray`/`memoryview` for as long as the `PyBuffer` is alive.
- The Rust `&[u8]` derived from it must not outlive the `PyBuffer`.

**Forbidden pattern** (would corrupt Python state):
```rust
fn bad_pattern(buf: PyBuffer<u8>) -> Vec<&'static [u8]> {
    // Storing the slice past PyBuffer's lifetime = use-after-free
    todo!()
}
```

**Required pattern**: the Rust function either (a) processes the buffer eagerly and returns owned data, or (b) returns an iterator that holds a `Py<PyAny>` reference to the original buffer to extend its lifetime.

### GIL handling rules:

- **Always** wrap long-running Rust computation in `py.detach(|| ...)`. This detaches from the interpreter so Python threads (e.g., the asyncio event loop) keep running.
- **Never** call PyO3 reflection APIs (Python object access) while in `detach`. The thread is detached; touching Python-bound values there violates PyO3's safety contract.
- **CPU-bound operations** (CDC scan, BLAKE3 hash, AEAD encrypt) always release the GIL.
- **I/O-bound operations** (chunk_store writes, WAL fsync) always release the GIL.
- **Quick metadata lookups** (memtable get) may hold the GIL; cost is microseconds.

### Error model:

```rust
// ol_chunk/src/lib.rs

use pyo3::create_exception;

create_exception!(ol_chunk, OlError, pyo3::exceptions::PyException);
create_exception!(ol_chunk, OlChunkError, OlError);

#[derive(Debug, thiserror::Error)]
pub enum ChunkError {
    #[error("buffer too small: need {needed}, got {got}")]
    BufferTooSmall { needed: usize, got: usize },

    #[error("invalid CDC parameters: {0}")]
    InvalidParameters(String),

    // ...
}

impl From<ChunkError> for PyErr {
    fn from(err: ChunkError) -> PyErr {
        OlChunkError::new_err(err.to_string())
    }
}
```

Python sees:
```python
try:
    ol_chunk.cdc_iter(small_buf)
except ol_chunk.OlChunkError as e:
    # Specific handling
```

### Build & install:

```bash
# Dev install (editable, rebuilds Rust on Python import)
cd One_link/native
maturin develop --release

# Build wheel for distribution
maturin build --release

# CI test
maturin develop --release && pytest tests/native/
```

`pyproject.toml` in `One_link/native/`:
```toml
[build-system]
requires = ["maturin>=1.5,<2.0"]
build-backend = "maturin"

[project]
name = "one-link-native"
version = "0.21.0a0"  # Aligned with file-engine v2 minor-arc; not the parent project version
requires-python = ">=3.11"

[tool.maturin]
features = ["pyo3/extension-module", "pyo3/abi3-py311"]
```

### Cross-platform builds:

- **Linux**: `manylinux2014` wheel via cibuildwheel + maturin. AVX-512 dispatched at runtime; reference scalar always shipped.
- **macOS**: universal2 (x86_64 + arm64) wheel via cibuildwheel; NEON on arm64.
- **Windows**: x86_64 wheel; AVX-512 dispatched at runtime if CPUID present.

### Versioning:

The native crate version (`0.21.0a0` for A1) is **independent** of the One Link parent version (`0.20.6` at A1 start). Semver:

- Bump minor when a new crate is added or a Phase ships its acceptance gate.
- Bump major when an FFI-breaking change occurs (rare; crate APIs are stable from A1 acceptance onward).
- The Python daemon depends on `one-link-native >= 0.21, < 1.0` during the A-arc.

## Consequences

**Positive:**
- Existing Python daemon's import pattern (it imports `one_link.native_cdc` today) ports trivially to `import ol_chunk`.
- `maturin develop` is the standard Rust-Python dev workflow; well-supported, well-documented.
- pyo3 + abi3 = single wheel works across Python 3.11+. No per-Python-version build matrix.
- GIL released for hot-path operations means Python orchestration concurrency unaffected by Rust work.
- Zero-copy buffer passing = no per-chunk memory copy overhead at the FFI boundary.
- Error model maps Rust errors to typed Python exceptions; Python catches with normal `except` semantics.

**Negative:**
- pyo3 + maturin add a build dependency on Rust. Already required by the architectural decision; not new cost.
- abi3 means Python-version-independent ABI, but pyo3 features (e.g., `pyo3::types::PyTuple` improvements) lag stable Python; we pin pyo3 minor versions.
- Cross-platform CI matrix becomes: Linux (manylinux), macOS universal2, Windows x86_64. cibuildwheel handles this; cost is in CI resources.
- pyo3 ABI changes between major versions (0.x → 0.y); planned upgrades require touching every binding crate. Mitigation: a thin "ol_pyo3_compat" wrapper crate that other crates depend on, isolating breakage.

## Verification

1. **Build gate**: `maturin develop --release` succeeds on Linux + macOS + Windows in CI. All test crates import without error.
2. **GIL-release gate**: while a `cdc_iter` call is in progress over 1 GiB of data, a Python `threading.Thread` running a 1ms loop continues making progress (verifies GIL released).
3. **Buffer lifetime gate**: pyo3 buffer-protocol fuzz: pass `bytes`, `bytearray`, `memoryview`, slice views; all must work; none corrupt Python state.
4. **Error mapping gate**: every `Result<T, ChunkError>::Err` variant produces a recognizable Python exception (`OlChunkError` subclass) with informative message.
5. **Wheel build gate**: `maturin build --release` produces a wheel that installs and imports on a clean venv.
6. **Cross-version gate**: wheel built against Python 3.11 abi3 imports under Python 3.12, 3.13, 3.14.

## References

- pyo3: https://pyo3.rs/ (the canonical Rust-Python bindings library).
- maturin: https://www.maturin.rs/ (the build tool; replaces setuptools-rust).
- abi3 stable Python ABI: PEP 384.
- cibuildwheel: https://cibuildwheel.readthedocs.io/ (used for cross-platform CI wheel builds).
- Existing C extension pattern: `src/one_link/native_cdc.py` (the precedent we mirror with Rust).
