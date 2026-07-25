"""Types for :mod:`one_link_native.selector`."""

from typing import Self, TypedDict, final, type_check_only

__version__: str

@type_check_only
class Decision(TypedDict):
    transport: str
    path: str
    onion_hops: int
    cover_traffic: bool
    batch_decision: str
    anchor_lay: bool
    predictor_warm: bool

@type_check_only
class Weights(TypedDict):
    alpha_coherence: float
    privacy_weight: float
    cover_penalty: float
    anchor_cost: float
    batch_latency_cost: float
    onion_hop_cost: float
    relay_rtt_multiplier: float
    lambda_dynamic: float
    dark_base: float
    dark_coherence: float
    dark_cover: float

@type_check_only
class LearnerStats(TypedDict):
    n_observations: int
    sum_abs_regret: float
    mean_abs_regret: float
    learning_rate: float
    regularization: float
    clamp_events: int

@final
class SmartRules:
    def __init__(self) -> None: ...
    def decide(
        self,
        *,
        kind: str,
        size: int,
        peer: str,
        urgency: str | None = ...,
        radio_state: str = ...,
        network: str = ...,
        user_mode: str = ...,
        observed_loss: float = ...,
        pattern_strength: float = ...,
    ) -> Decision: ...
    def safe_default(self) -> Decision: ...
    def name(self) -> str: ...
    def __repr__(self) -> str: ...

@final
class UnifiedMin:
    def __init__(self) -> None: ...
    @staticmethod
    def with_weights(
        alpha_coherence: float | None = ...,
        privacy_weight: float | None = ...,
        cover_penalty: float | None = ...,
        anchor_cost: float | None = ...,
        batch_latency_cost: float | None = ...,
        onion_hop_cost: float | None = ...,
        relay_rtt_multiplier: float | None = ...,
        lambda_dynamic: float | None = ...,
        dark_base: float | None = ...,
        dark_coherence: float | None = ...,
        dark_cover: float | None = ...,
    ) -> UnifiedMin: ...
    def weights(self) -> Weights: ...
    def decide(
        self,
        *,
        kind: str,
        size: int,
        peer: str,
        urgency: str | None = ...,
        radio_state: str = ...,
        network: str = ...,
        user_mode: str = ...,
        observed_loss: float = ...,
        pattern_strength: float = ...,
    ) -> Decision: ...
    def safe_default(self) -> Decision: ...
    def name(self) -> str: ...
    def __repr__(self) -> str: ...

@final
class OnlineLearner:
    def __new__(
        cls,
        learning_rate: float = ...,
        regularization: float = ...,
        weight_bound_multiplier: float = ...,
    ) -> Self: ...
    def weights(self) -> Weights: ...
    def defaults(self) -> Weights: ...
    def decide(
        self,
        *,
        kind: str,
        size: int,
        peer: str,
        urgency: str | None = ...,
        radio_state: str = ...,
        network: str = ...,
        user_mode: str = ...,
        observed_loss: float = ...,
        pattern_strength: float = ...,
    ) -> Decision: ...
    def observe(
        self,
        regret: float,
        decision: Decision,
        *,
        kind: str,
        size: int,
        peer: str,
        urgency: str | None = ...,
        radio_state: str = ...,
        network: str = ...,
        user_mode: str = ...,
        observed_loss: float = ...,
        pattern_strength: float = ...,
    ) -> None: ...
    def stats(self) -> LearnerStats: ...
    def name(self) -> str: ...
    def __repr__(self) -> str: ...
