//! `one_link_native.bandit` — Python binding for `ol_bandit`.
//!
//! Exposes the Beta-Bernoulli Thompson sampling bandit per ADR-0019.
//! The daemon's `transfer_brain.py` (currently using EMA route memory)
//! replaces its arm-selection loop with calls into this binding.

use ol_bandit::{Bandit, BanditError, BanditSeed};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;

/// Python-visible bandit.
#[pyclass(name = "Bandit", module = "one_link_native.bandit")]
#[derive(Debug, Clone)]
pub struct PyBandit {
    inner: Bandit,
    rng: BanditSeed,
}

#[pymethods]
impl PyBandit {
    /// Build a fresh bandit with `n_arms` arms (uniform Beta(1, 1) priors).
    ///
    /// `seed` defaults to a derived constant; pass a u64 for
    /// deterministic test replays.
    #[new]
    #[pyo3(signature = (n_arms, seed = 0xBABE_F00D))]
    fn new(n_arms: usize, seed: u64) -> PyResult<Self> {
        let inner = Bandit::new(n_arms).map_err(bandit_err_to_py)?;
        Ok(Self {
            inner,
            rng: BanditSeed::new(seed),
        })
    }

    /// Number of arms.
    #[getter]
    fn n_arms(&self) -> usize {
        self.inner.n_arms()
    }

    /// Thompson-sample an arm to play.
    fn select(&mut self) -> usize {
        self.inner.select(&mut self.rng)
    }

    /// Update with the observed reward `r in [0, 1]` for `arm_idx`.
    fn update(&mut self, arm_idx: usize, reward: f64) -> PyResult<()> {
        self.inner.update(arm_idx, reward).map_err(bandit_err_to_py)
    }

    /// The arm with the highest posterior mean.
    fn best_arm(&self) -> usize {
        self.inner.best_arm()
    }

    /// Per-arm `(alpha, beta)` tuples for diagnostics.
    fn arms<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty_bound(py);
        for arm in self.inner.arms() {
            out.append((arm.alpha, arm.beta))?;
        }
        Ok(out)
    }

    /// Reset the internal RNG to `seed` (test/replay use only).
    fn reseed(&mut self, seed: u64) {
        self.rng = BanditSeed::new(seed);
    }

    fn __repr__(&self) -> String {
        format!(
            "Bandit(n_arms={}, best_arm={})",
            self.inner.n_arms(),
            self.inner.best_arm()
        )
    }
}

fn bandit_err_to_py(err: BanditError) -> PyErr {
    match err {
        BanditError::InvalidReward { got } => {
            PyValueError::new_err(format!("invalid reward: {got}"))
        }
        other => crate::errors::OlBanditError::new_err(other.to_string()),
    }
}

/// Register the `bandit` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_bandit::VERSION)?;
    m.add_class::<PyBandit>()?;
    Ok(())
}
