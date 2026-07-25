//! `one_link_native.hwkey` — Python binding for `ol_hwkey`.
//!
//! Surfaces the `KeyStore` abstraction (ADR-0023). This drop exposes
//! the always-available `TofuStore` fallback; platform-specific
//! backends slot in behind Cargo features later.

use ol_hwkey::{HwKeyError, KeyGuarantee, KeyHandle, KeyStore, PublicKey, TofuStore};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass(name = "TofuStore", module = "one_link_native.hwkey")]
#[derive(Debug)]
pub struct PyTofuStore {
    inner: TofuStore,
}

#[pymethods]
impl PyTofuStore {
    /// Build a fresh TOFU store seeded with `root` (32 bytes).
    #[new]
    fn new(root: &[u8]) -> PyResult<Self> {
        if root.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "root must be 32 bytes, got {}",
                root.len()
            )));
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(root);
        Ok(Self {
            inner: TofuStore::new(r),
        })
    }

    /// Returns one of "`TofuOnly`", "`HardwareBound`", "`HardwareAttested`".
    fn guarantee(&self) -> &'static str {
        match self.inner.guarantee() {
            KeyGuarantee::TofuOnly => "TofuOnly",
            KeyGuarantee::HardwareBound => "HardwareBound",
            KeyGuarantee::HardwareAttested => "HardwareAttested",
        }
    }

    /// Idempotent: returns the handle label string.
    fn get_or_create(&self, label: &str) -> PyResult<String> {
        self.inner
            .get_or_create(label)
            .map(|h| h.0)
            .map_err(|err| hwkey_err_to_py(&err))
    }

    /// 32-byte public key for the given handle.
    fn public_key<'py>(&self, py: Python<'py>, label: &str) -> PyResult<Bound<'py, PyBytes>> {
        let h = KeyHandle(label.to_string());
        let pk = self
            .inner
            .public_key(&h)
            .map_err(|err| hwkey_err_to_py(&err))?;
        Ok(PyBytes::new(py, &pk.0))
    }

    /// True iff the presented public key matches the one recorded on
    /// first use; False if it's a TOFU rotation; raises on `NotFound`.
    fn check_tofu(&self, label: &str, presented: &[u8]) -> PyResult<bool> {
        if presented.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "presented public key must be 32 bytes, got {}",
                presented.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(presented);
        let pk = PublicKey(arr);
        match self.inner.check_tofu(label, &pk) {
            Ok(()) => Ok(true),
            Err(HwKeyError::TofuMismatch) => Ok(false),
            Err(other) => Err(hwkey_err_to_py(&other)),
        }
    }

    fn __repr__(&self) -> String {
        format!("TofuStore(guarantee={})", self.guarantee())
    }
}

fn hwkey_err_to_py(err: &HwKeyError) -> PyErr {
    crate::errors::OlHwKeyError::new_err(err.to_string())
}

/// Register the `hwkey` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTofuStore>()?;
    Ok(())
}
