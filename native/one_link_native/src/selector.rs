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
use ol_selector::{
    BatchDecision, Decision, OnlineLearner, Path, SmartRules, Transport, UnifiedMin, Weights,
};
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
        Self { inner: SmartRules }
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
    let k =
        EventKind::from_wire_type(kind).map_err(|e| PyValueError::new_err(format!("kind: {e}")))?;
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

/// Phase H — Python-visible UnifiedMin selector.
///
/// Continuous energy-minimization variant: enumerates a small candidate
/// grid filtered through F4 contract validation, then picks the one
/// that minimizes the parameterized energy objective. Same Decide<Decision>
/// surface as SmartRules; daemon swap is a one-line change.
#[pyclass(name = "UnifiedMin", module = "one_link_native.selector")]
#[derive(Debug, Clone, Copy)]
pub struct PyUnifiedMin {
    inner: UnifiedMin,
}

#[pymethods]
impl PyUnifiedMin {
    /// Construct with the canonical default weights.
    #[new]
    fn new() -> Self {
        Self {
            inner: UnifiedMin::new(),
        }
    }

    /// Construct with explicit per-term weights. Use this for
    /// experimentation / Phase I online-learning checkpoints.
    ///
    /// Pass the same 11 fields the Rust [`Weights`] struct exposes;
    /// missing fields default to the canonical values.
    #[staticmethod]
    #[pyo3(signature = (
        alpha_coherence = None,
        privacy_weight = None,
        cover_penalty = None,
        anchor_cost = None,
        batch_latency_cost = None,
        onion_hop_cost = None,
        relay_rtt_multiplier = None,
        lambda_dynamic = None,
        dark_base = None,
        dark_coherence = None,
        dark_cover = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn with_weights(
        alpha_coherence: Option<f32>,
        privacy_weight: Option<f32>,
        cover_penalty: Option<f32>,
        anchor_cost: Option<f32>,
        batch_latency_cost: Option<f32>,
        onion_hop_cost: Option<f32>,
        relay_rtt_multiplier: Option<f32>,
        lambda_dynamic: Option<f32>,
        dark_base: Option<f32>,
        dark_coherence: Option<f32>,
        dark_cover: Option<f32>,
    ) -> Self {
        let mut w = Weights::defaults();
        if let Some(v) = alpha_coherence {
            w.alpha_coherence = v;
        }
        if let Some(v) = privacy_weight {
            w.privacy_weight = v;
        }
        if let Some(v) = cover_penalty {
            w.cover_penalty = v;
        }
        if let Some(v) = anchor_cost {
            w.anchor_cost = v;
        }
        if let Some(v) = batch_latency_cost {
            w.batch_latency_cost = v;
        }
        if let Some(v) = onion_hop_cost {
            w.onion_hop_cost = v;
        }
        if let Some(v) = relay_rtt_multiplier {
            w.relay_rtt_multiplier = v;
        }
        if let Some(v) = lambda_dynamic {
            w.lambda_dynamic = v;
        }
        if let Some(v) = dark_base {
            w.dark_base = v;
        }
        if let Some(v) = dark_coherence {
            w.dark_coherence = v;
        }
        if let Some(v) = dark_cover {
            w.dark_cover = v;
        }
        Self {
            inner: UnifiedMin::with_weights(w),
        }
    }

    /// Read the current weights as a dict.
    fn weights<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let w = &self.inner.weights;
        let d = PyDict::new_bound(py);
        d.set_item("alpha_coherence", w.alpha_coherence)?;
        d.set_item("privacy_weight", w.privacy_weight)?;
        d.set_item("cover_penalty", w.cover_penalty)?;
        d.set_item("anchor_cost", w.anchor_cost)?;
        d.set_item("batch_latency_cost", w.batch_latency_cost)?;
        d.set_item("onion_hop_cost", w.onion_hop_cost)?;
        d.set_item("relay_rtt_multiplier", w.relay_rtt_multiplier)?;
        d.set_item("lambda_dynamic", w.lambda_dynamic)?;
        d.set_item("dark_base", w.dark_base)?;
        d.set_item("dark_coherence", w.dark_coherence)?;
        d.set_item("dark_cover", w.dark_cover)?;
        Ok(d)
    }

    /// Decide for one event. Same signature as SmartRules.decide
    /// (the kwargs interface is intentionally identical so the daemon
    /// can A/B test by swapping selector class).
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

    /// safe_default — for parity with SmartRules.
    fn safe_default<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        decision_to_dict(py, Decision::safe_default())
    }

    /// Stable name for telemetry: "UnifiedMin".
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn __repr__(&self) -> String {
        format!(
            "UnifiedMin(privacy_weight={}, alpha_coherence={})",
            self.inner.weights.privacy_weight, self.inner.weights.alpha_coherence,
        )
    }
}

/// Phase I — Python-visible OnlineLearner.
///
/// Wraps UnifiedMin with an `observe(ctx, decision, regret)` method
/// that runs analytic gradient descent on the per-term weights from
/// production feedback. Designed as opt-in: production daemons run
/// with a fresh OnlineLearner only when ONE_LINK_ONLINE_LEARN=1.
#[pyclass(name = "OnlineLearner", module = "one_link_native.selector")]
pub struct PyOnlineLearner {
    inner: OnlineLearner,
}

#[pymethods]
impl PyOnlineLearner {
    /// Construct with canonical defaults.
    #[new]
    #[pyo3(signature = (
        learning_rate = 0.001,
        regularization = 0.01,
        weight_bound_multiplier = 10.0,
    ))]
    fn new(learning_rate: f32, regularization: f32, weight_bound_multiplier: f32) -> Self {
        Self {
            inner: OnlineLearner::with_config(
                Weights::defaults(),
                learning_rate,
                regularization,
                weight_bound_multiplier,
            ),
        }
    }

    /// Read the current learned weights as a dict.
    fn weights<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let w = self.inner.weights();
        let d = PyDict::new_bound(py);
        d.set_item("alpha_coherence", w.alpha_coherence)?;
        d.set_item("privacy_weight", w.privacy_weight)?;
        d.set_item("cover_penalty", w.cover_penalty)?;
        d.set_item("anchor_cost", w.anchor_cost)?;
        d.set_item("batch_latency_cost", w.batch_latency_cost)?;
        d.set_item("onion_hop_cost", w.onion_hop_cost)?;
        d.set_item("relay_rtt_multiplier", w.relay_rtt_multiplier)?;
        d.set_item("lambda_dynamic", w.lambda_dynamic)?;
        d.set_item("dark_base", w.dark_base)?;
        d.set_item("dark_coherence", w.dark_coherence)?;
        d.set_item("dark_cover", w.dark_cover)?;
        Ok(d)
    }

    /// Frozen factory defaults (the regularization anchor).
    fn defaults<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let w = self.inner.defaults();
        let d = PyDict::new_bound(py);
        d.set_item("alpha_coherence", w.alpha_coherence)?;
        d.set_item("privacy_weight", w.privacy_weight)?;
        d.set_item("cover_penalty", w.cover_penalty)?;
        d.set_item("anchor_cost", w.anchor_cost)?;
        d.set_item("batch_latency_cost", w.batch_latency_cost)?;
        d.set_item("onion_hop_cost", w.onion_hop_cost)?;
        d.set_item("relay_rtt_multiplier", w.relay_rtt_multiplier)?;
        d.set_item("lambda_dynamic", w.lambda_dynamic)?;
        d.set_item("dark_base", w.dark_base)?;
        d.set_item("dark_coherence", w.dark_coherence)?;
        d.set_item("dark_cover", w.dark_cover)?;
        Ok(d)
    }

    /// Decide as the underlying UnifiedMin would.
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

    /// Record one observation. The (ctx, decision) tuple is the
    /// daemon's chosen action; `regret` is the observed cost above
    /// what the model anticipated (positive = bad outcome, negative
    /// = better than expected).
    ///
    /// `decision` accepts a dict matching the shape returned by
    /// `decide(...)`. Fields used: transport, path, onion_hops,
    /// cover_traffic, batch_decision, anchor_lay, predictor_warm.
    #[pyo3(signature = (
        regret,
        decision,
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
    fn observe(
        &mut self,
        regret: f32,
        decision: &Bound<'_, PyDict>,
        kind: &str,
        size: usize,
        peer: &str,
        urgency: Option<&str>,
        radio_state: &str,
        network: &str,
        user_mode: &str,
        observed_loss: f32,
        pattern_strength: f32,
    ) -> PyResult<()> {
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
        let d = decision_from_dict(decision)?;
        self.inner.observe(&ctx, &d, regret);
        Ok(())
    }

    /// Lifetime statistics dict.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.inner.stats();
        let d = PyDict::new_bound(py);
        d.set_item("n_observations", s.n_observations)?;
        d.set_item("sum_abs_regret", s.sum_abs_regret)?;
        d.set_item("mean_abs_regret", s.mean_abs_regret)?;
        d.set_item("learning_rate", s.learning_rate)?;
        d.set_item("regularization", s.regularization)?;
        d.set_item("clamp_events", s.clamp_events)?;
        Ok(d)
    }

    fn name(&self) -> &'static str {
        "OnlineLearner"
    }

    fn __repr__(&self) -> String {
        let s = self.inner.stats();
        format!(
            "OnlineLearner(n_obs={}, mean_abs_regret={:.3}, clamps={})",
            s.n_observations, s.mean_abs_regret, s.clamp_events,
        )
    }
}

fn decision_from_dict(d: &Bound<'_, PyDict>) -> PyResult<Decision> {
    use ol_selector::OnionHops;
    let transport = d
        .get_item("transport")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'transport'"))?
        .extract::<String>()?;
    let path = d
        .get_item("path")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'path'"))?
        .extract::<String>()?;
    let onion_hops = d
        .get_item("onion_hops")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'onion_hops'"))?
        .extract::<u8>()?;
    let cover_traffic = d
        .get_item("cover_traffic")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'cover_traffic'"))?
        .extract::<bool>()?;
    let batch_decision = d
        .get_item("batch_decision")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'batch_decision'"))?
        .extract::<String>()?;
    let anchor_lay = d
        .get_item("anchor_lay")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'anchor_lay'"))?
        .extract::<bool>()?;
    let predictor_warm = d
        .get_item("predictor_warm")?
        .ok_or_else(|| PyValueError::new_err("decision missing 'predictor_warm'"))?
        .extract::<bool>()?;

    let t = match transport.to_ascii_lowercase().as_str() {
        "quic_stream" => Transport::QuicStream,
        "quic_datagram" => Transport::QuicDatagram,
        "webrtc" => Transport::WebRtc,
        "relay" => Transport::Relay,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown transport: {other:?}"
            )))
        }
    };
    let p = match path.to_ascii_lowercase().as_str() {
        "classical" => Path::Classical,
        "coherence" => Path::Coherence,
        other => return Err(PyValueError::new_err(format!("unknown path: {other:?}"))),
    };
    let h = OnionHops::from_u8(onion_hops).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let b = match batch_decision.to_ascii_lowercase().as_str() {
        "emit_now" => BatchDecision::EmitNow,
        "batch" => BatchDecision::Batch,
        "urgent_bypass" => BatchDecision::UrgentBypass,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown batch_decision: {other:?}"
            )))
        }
    };
    Ok(Decision {
        transport: t,
        path: p,
        onion_hops: h,
        cover_traffic,
        batch_decision: b,
        anchor_lay,
        predictor_warm,
    })
}

/// Register the `selector` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_selector::VERSION)?;
    m.add_class::<PySmartRules>()?;
    m.add_class::<PyUnifiedMin>()?;
    m.add_class::<PyOnlineLearner>()?;
    Ok(())
}
