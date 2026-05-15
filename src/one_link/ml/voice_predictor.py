"""Production voice MFCC next-frame predictor.

Architecture:
  * Input:   MFCC frame (feature_dim = n_mfcc * 3 with deltas) = 60
  * Embedding: linear projection feature_dim -> hidden_dim
  * Core:    2-layer GRU, bidirectional=False (causal), hidden=256
  * Head:    2 branches
             (a) next-frame regression head: linear -> feature_dim
             (b) next-phoneme classification head: linear -> n_phonemes

Trained jointly with:
  * MSE loss on next-frame MFCC prediction (primary signal for the
    coherence-prior decoder)
  * Cross-entropy loss on next phoneme class (auxiliary, helps
    structure)

The model's "prediction accuracy" metric for the coherence_prior layer
is derived from 1 - normalized MFCC prediction error, clipped to
[0, 1]. This is what the .cl voice code treats as `p` in
`1 / (1 - p)` throughput multiplier.

Public:
    VoicePredictor(cfg)             -- nn.Module
    VoicePredictorConfig            -- dataclass of hyperparams
    compute_predictive_accuracy(mfcc_target, mfcc_predicted) -> float
"""

from __future__ import annotations

import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import numpy as np

try:
    import torch
    import torch.nn as nn
except Exception as e:  # noqa: BLE001
    print(f"[voice_predictor] torch not available: {e}", file=sys.stderr)
    raise


from one_link.ml.speech_synth import PHONEME_NAMES  # noqa: E402


@dataclass
class VoicePredictorConfig:
    feature_dim: int = 60
    hidden_dim: int = 256
    n_layers: int = 2
    dropout: float = 0.1
    n_phonemes: int = 19


class VoicePredictor(nn.Module):
    def __init__(self, cfg: VoicePredictorConfig):
        super().__init__()
        self.cfg = cfg
        self.embed = nn.Linear(cfg.feature_dim, cfg.hidden_dim)
        self.gru = nn.GRU(
            input_size=cfg.hidden_dim,
            hidden_size=cfg.hidden_dim,
            num_layers=cfg.n_layers,
            dropout=cfg.dropout if cfg.n_layers > 1 else 0.0,
            batch_first=True,
        )
        self.mfcc_head = nn.Linear(cfg.hidden_dim, cfg.feature_dim)
        self.phoneme_head = nn.Linear(cfg.hidden_dim, cfg.n_phonemes)

    def forward(self, x: "torch.Tensor",
                h0: Optional["torch.Tensor"] = None):
        """x: (B, T, feature_dim); returns (mfcc_pred, phone_logits, h_last).

        mfcc_pred and phone_logits shape (B, T, ...) with timestep t
        predicting the value at t+1 (causal shift handled by caller loss)."""
        e = self.embed(x)
        y, hn = self.gru(e, h0)
        mfcc_pred = self.mfcc_head(y)
        phone_logits = self.phoneme_head(y)
        return mfcc_pred, phone_logits, hn


# =============================================================================
# ACCURACY CALCULATION (for coherence-prior `p`)
# =============================================================================

def compute_predictive_accuracy(target: np.ndarray, predicted: np.ndarray,
                                sigma: float = 1.0) -> float:
    """Map per-frame MFCC prediction error to a [0, 1] `p` value suitable
    for the coherence_prior formula `1 / (1 - p)`.

    Mapping: p = exp(-||e||^2 / (2 * sigma^2 * feature_dim))
    sigma is tuned on validation set so that perfect reconstruction -> ~0.999
    and random noise -> ~0.01.
    """
    err = target - predicted
    # Per-frame squared L2, averaged over feature_dim.
    fd = float(err.shape[-1])
    per_frame_err = np.mean(err ** 2, axis=-1)
    p_per = np.exp(-per_frame_err / (2.0 * sigma * sigma))
    return float(np.mean(p_per))


# =============================================================================
# SELFTEST
# =============================================================================

def _selftest() -> int:
    cfg = VoicePredictorConfig()
    model = VoicePredictor(cfg)
    # Count params
    n_params = sum(p.numel() for p in model.parameters())
    assert n_params > 10_000, f"model too small: {n_params}"
    # Forward pass on dummy input
    x = torch.randn(2, 50, cfg.feature_dim)
    mfcc_pred, phone_logits, hn = model(x)
    assert mfcc_pred.shape == (2, 50, cfg.feature_dim)
    assert phone_logits.shape == (2, 50, cfg.n_phonemes)
    assert hn.shape == (cfg.n_layers, 2, cfg.hidden_dim)

    # Accuracy calc
    tgt = np.random.randn(10, 60).astype(np.float32)
    pr = tgt + np.random.randn(10, 60).astype(np.float32) * 0.01
    p_good = compute_predictive_accuracy(tgt, pr, sigma=0.5)
    p_bad = compute_predictive_accuracy(tgt, np.zeros_like(tgt), sigma=0.5)
    assert p_good > 0.95
    assert p_bad < 0.5

    print(f"voice_predictor selftest: OK  "
          f"(n_params={n_params:,} p_good={p_good:.4f} p_bad={p_bad:.4f})")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
