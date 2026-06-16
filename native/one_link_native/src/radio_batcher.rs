//! `one_link_native.radio_batcher` — Python binding for `ol_radio_batcher`.
//!
//! Wraps the deterministic batcher with `bytes`-typed payloads for use
//! from the daemon's broadcast loop (daemon.py:12137-12140). The
//! daemon enqueues `(peer_fp, outer_frame, priority)` and drains on
//! the 20s `_prune_loop` tick (daemon.py:16964-16986).

use ol_radio_batcher::{Batcher, BatcherError, BatcherStats, DrainOutcome, Priority, RadioState};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

/// Python-visible radio batcher with bytes payloads.
///
/// One instance per daemon is the intended usage; the daemon caches
/// `self.batcher = RadioBatcher()` in its constructor.
#[pyclass(name = "RadioBatcher", module = "one_link_native.radio_batcher")]
pub struct PyRadioBatcher {
    inner: Batcher<Vec<u8>>,
}

#[pymethods]
impl PyRadioBatcher {
    /// Construct with default tuning: 50ms DRX window, 4096 queue cap,
    /// 20s force-age.
    #[new]
    #[pyo3(signature = (drx_window_ms = 50, max_queue_size = 4096, max_age_ms = 20_000))]
    fn new(drx_window_ms: u32, max_queue_size: usize, max_age_ms: u32) -> PyResult<Self> {
        let inner = Batcher::with_config(drx_window_ms, max_queue_size, max_age_ms)
            .map_err(batcher_err_to_py)?;
        Ok(Self { inner })
    }

    /// Enqueue a payload for batched delivery.
    ///
    /// `priority` accepts `"urgent"` / `"normal"` / `"background"`
    /// (case-insensitive). `now_ms` is the current wall-clock in
    /// milliseconds (the caller injects time).
    ///
    /// Raises `ValueError` with code `"queue_full"` when the queue is
    /// at `max_queue_size`. The daemon's safe response is to fall
    /// back to direct emit.
    #[pyo3(signature = (peer_fp, payload, priority, now_ms))]
    fn enqueue(
        &mut self,
        peer_fp: &str,
        payload: Vec<u8>,
        priority: &str,
        now_ms: u64,
    ) -> PyResult<()> {
        let p = parse_priority(priority)?;
        self.inner
            .enqueue(peer_fp.to_owned(), payload, p, now_ms)
            .map_err(batcher_err_to_py)
    }

    /// Drain all entries eligible to send at `now_ms`.
    ///
    /// Returns a tuple `(entries, outcome)` where:
    ///   - entries: list of dicts with keys "peer_fp", "payload",
    ///     "priority", "enqueued_at_ms"
    ///   - outcome: dict with keys "drained", "remaining",
    ///     "force_drained_due_to_age"
    fn drain<'py>(
        &mut self,
        py: Python<'py>,
        now_ms: u64,
    ) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyDict>)> {
        let (drained, outcome) = self.inner.drain(now_ms);
        let list = PyList::empty_bound(py);
        for entry in drained {
            let d = PyDict::new_bound(py);
            d.set_item("peer_fp", entry.peer_fp)?;
            d.set_item("payload", PyBytes::new_bound(py, &entry.payload))?;
            d.set_item("priority", priority_str(entry.priority))?;
            d.set_item("enqueued_at_ms", entry.enqueued_at_ms)?;
            list.append(d)?;
        }
        Ok((list, drain_outcome_to_dict(py, outcome)?))
    }

    /// Force-drain everything regardless of age. Used at shutdown.
    fn drain_all<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let drained = self.inner.drain_all();
        let list = PyList::empty_bound(py);
        for entry in drained {
            let d = PyDict::new_bound(py);
            d.set_item("peer_fp", entry.peer_fp)?;
            d.set_item("payload", PyBytes::new_bound(py, &entry.payload))?;
            d.set_item("priority", priority_str(entry.priority))?;
            d.set_item("enqueued_at_ms", entry.enqueued_at_ms)?;
            list.append(d)?;
        }
        Ok(list)
    }

    /// Set the observed radio state.
    ///
    /// `state` accepts `"active"` / `"short_drx"` / `"long_drx"`
    /// (case-insensitive). Unknown labels default to `"active"`.
    ///
    /// The deterministic core ignores this for scheduling; it's
    /// available to the daemon as an observability signal.
    fn set_radio_state(&mut self, state: &str) {
        self.inner
            .set_radio_state(RadioState::from_label_or_default(state));
    }

    /// Current observed radio state as a label.
    fn radio_state(&self) -> &'static str {
        self.inner.radio_state().as_str()
    }

    /// Current queue length.
    #[getter]
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff the queue is empty.
    #[getter]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Configured DRX window in milliseconds.
    #[getter]
    fn drx_window_ms(&self) -> u32 {
        self.inner.drx_window_ms()
    }

    /// Aggregate counters since construction.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.inner.stats();
        stats_to_dict(py, s)
    }

    fn __repr__(&self) -> String {
        format!(
            "RadioBatcher(len={}, drx_window_ms={}, radio_state={:?})",
            self.inner.len(),
            self.inner.drx_window_ms(),
            self.inner.radio_state().as_str(),
        )
    }
}

fn parse_priority(s: &str) -> PyResult<Priority> {
    match s.to_ascii_lowercase().as_str() {
        "urgent" => Ok(Priority::Urgent),
        "normal" => Ok(Priority::Normal),
        "background" | "bg" => Ok(Priority::Background),
        other => Err(PyValueError::new_err(format!(
            "unknown priority: {other:?} (expected urgent|normal|background)"
        ))),
    }
}

fn priority_str(p: Priority) -> &'static str {
    match p {
        Priority::Urgent => "urgent",
        Priority::Normal => "normal",
        Priority::Background => "background",
    }
}

fn batcher_err_to_py(err: BatcherError) -> PyErr {
    match err {
        BatcherError::QueueFull { size, max } => {
            let msg = format!("queue_full: size={size}, max={max}");
            PyValueError::new_err(msg)
        }
        other => PyValueError::new_err(other.to_string()),
    }
}

fn drain_outcome_to_dict<'py>(py: Python<'py>, o: DrainOutcome) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("drained", o.drained)?;
    d.set_item("remaining", o.remaining)?;
    d.set_item("force_drained_due_to_age", o.force_drained_due_to_age)?;
    Ok(d)
}

fn stats_to_dict<'py>(py: Python<'py>, s: BatcherStats) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("enqueued_total", s.enqueued_total)?;
    d.set_item("drained_total", s.drained_total)?;
    d.set_item("rejected_full", s.rejected_full)?;
    d.set_item("aged_out", s.aged_out)?;
    Ok(d)
}

/// Register the `radio_batcher` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_radio_batcher::VERSION)?;
    m.add(
        "DEFAULT_DRX_WINDOW_MS",
        ol_radio_batcher::DEFAULT_DRX_WINDOW_MS,
    )?;
    m.add(
        "DEFAULT_MAX_QUEUE_SIZE",
        ol_radio_batcher::DEFAULT_MAX_QUEUE_SIZE,
    )?;
    m.add("DEFAULT_MAX_AGE_MS", ol_radio_batcher::DEFAULT_MAX_AGE_MS)?;
    m.add_class::<PyRadioBatcher>()?;
    Ok(())
}
