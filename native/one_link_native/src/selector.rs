//! `one_link_native.selector` — Python binding for `ol_selector`.
//!
//! Exposes the Smart-Rules per-event selector. The daemon's `send_file`
//! decision point (daemon.py:14020-14080) consumes this via a Decision
//! dict; future selector variants (UnifiedMin in Phase H) plug in
//! through the same `Decide<Decision>` trait without disturbing this
//! Python surface.

use ol_decide::{
    Context, Decide, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode,
};
use ol_selector::{BatchDecision, Decision, Path, SmartRules, Transport};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Python-visible Smart-Rules selector.
#[pyclass(name = "SmartRules", module = "one_link_native.selector")]
#[derive(Debug, Clone, Copy, Default)]
pub struct PySmartRules {
    inner: SmartRules,
}

#[pymethods]
impl PySmartRules {
    /// Construct. Stateless; one instance is fine for the whole daemon.
    #[new]
    fn new() -> Self {
        Self {
            inner: SmartRules,
        }
    }

    /// Decide for one event.
    ///
    /// All keyword arguments correspond to fields on the `Context`
    /// struct. String enums (`kind`, `peer`, `urgency`, `radio_state`,
    /// `network`, `user_mode`) accept the daemon's existing label
    /// vocabulary (see `wire.py`, `state.py`, `align_native.py`).
    ///
    /// Numeric ranges:
    ///   - `size`              non-negative integer
    ///   - `observed_loss`     [0.0, 1.0]
    ///   - `pattern_strength`  [0.0, 1.0]
    ///
    /// Defaults: `urgency` derives from `kind`; `radio_state` defaults
    /// to "active"; `network` defaults to "wifi"; `user_mode` defaults
    /// to "normal"; `observed_loss` and `pattern_strength` default to 0.
    ///
    /// Returns a dict with the 7 decision fields:
    ///   transport: "quic_stream" | "quic_datagram" | "webrtc" | "relay"
    ///   path: "classical" | "coherence"
    ///   onion_hops: 1 | 3 | 5
    ///   cover_traffic: bool
    ///   batch_decision: "emit_now" | "batch" | "urgent_bypass"
    ///   anchor_lay: bool
    ///   predictor_warm: bool
    #[pyo3(signature = (
        *,
        kind,
        size,
        peer,
        urgency = None,
        radio_state = "active",
        network = "wifi",
        user_mode = "normal",
        observed_loss = 0.0,
        pattern_strength = 0.0,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn decide<'py>(
        &self,
        py: Python<'py>,
        kind: &str,
        size: usize,
        peer: &str,
        urgency: Option<&str>,
        radio_state: &str,
        network: &str,
        user_mode: &str,
        observed_loss: f32,
        pattern_strength: f32,
    ) -> PyResult<Bound<'py, PyDict>> {
        let ctx = build_context_or_err(
            kind,
            size,
            peer,
            urgency,
            radio_state,
            network,
            user_mode,
            observed_loss,
            pattern_strength,
        )?;
        let d = self.inner.decide(&ctx);
        decision_to_dict(py, d)
    }

    /// The "safe-default" decision used as a fallback. Independent of
    /// context but accepts context-shape args for parity with `decide`.
    fn safe_default<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        decision_to_dict(py, Decision::safe_default())
    }

    /// Stable name for telemetry.
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn __repr__(&self) -> String {
        "SmartRules()".to_owned()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_context_or_err(
    kind: &str,
    size: usize,
    peer: &str,
    urgency: Option<&str>,
    radio_state: &str,
    network: &str,
    user_mode: &str,
    observed_loss: f32,
    pattern_strength: f32,
) -> PyResult<Context> {
    let k = EventKind::from_wire_type(kind)
        .map_err(|e| PyValueError::new_err(format!("kind: {e}")))?;
    let p = PeerRelationship::from_label(peer)
        .map_err(|e| PyValueError::new_err(format!("peer: {e}")))?;
    let u = match urgency {
        None => Urgency::from_kind(k),
        Some(s) => parse_urgency(s)?,
    };
    let r = parse_radio(radio_state)?;
    let n = parse_network(network)?;
    let m = UserMode::from_label_or_default(user_mode);
    Context::build(k, size, p, u, r, n, m, observed_loss, pattern_strength)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

fn parse_urgency(s: &str) -> PyResult<Urgency> {
    match s.to_ascii_lowercase().as_str() {
        "foreground" | "fg" => Ok(Urgency::Foreground),
        "background" | "bg" => Ok(Urgency::Background),
        other => Err(PyValueError::new_err(format!(
            "unknown urgency: {other:?} (expected foreground|background)"
        ))),
    }
}

fn parse_radio(s: &str) -> PyResult<RadioState> {
    match s.to_ascii_lowercase().as_str() {
        "active" => Ok(RadioState::Active),
        "short_drx" | "short-drx" | "shortdrx" => Ok(RadioState::ShortDrx),
        "long_drx" | "long-drx" | "longdrx" => Ok(RadioState::LongDrx),
        other => Err(PyValueError::new_err(format!(
            "unknown radio_state: {other:?} (expected active|short_drx|long_drx)"
        ))),
    }
}

fn parse_network(s: &str) -> PyResult<NetworkType> {
    match s.to_ascii_lowercase().as_str() {
        "wifi" | "wi-fi" => Ok(NetworkType::Wifi),
        "cellular" => Ok(NetworkType::Cellular),
        "metered" => Ok(NetworkType::Metered),
        other => Err(PyValueError::new_err(format!(
            "unknown network: {other:?} (expected wifi|cellular|metered)"
        ))),
    }
}

fn decision_to_dict<'py>(py: Python<'py>, d: Decision) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new_bound(py);
    out.set_item("transport", transport_str(d.transport))?;
    out.set_item("path", path_str(d.path))?;
    out.set_item("onion_hops", d.onion_hops.as_u8())?;
    out.set_item("cover_traffic", d.cover_traffic)?;
    out.set_item("batch_decision", batch_str(d.batch_decision))?;
    out.set_item("anchor_lay", d.anchor_lay)?;
    out.set_item("predictor_warm", d.predictor_warm)?;
    Ok(out)
}

fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::QuicStream => "quic_stream",
        Transport::QuicDatagram => "quic_datagram",
        Transport::WebRtc => "webrtc",
        Transport::Relay => "relay",
    }
}

fn path_str(p: Path) -> &'static str {
    match p {
        Path::Classical => "classical",
        Path::Coherence => "coherence",
    }
}

fn batch_str(b: BatchDecision) -> &'static str {
    match b {
        BatchDecision::EmitNow => "emit_now",
        BatchDecision::Batch => "batch",
        BatchDecision::UrgentBypass => "urgent_bypass",
    }
}

/// Register the `selector` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_selector::VERSION)?;
    m.add_class::<PySmartRules>()?;
    Ok(())
}
