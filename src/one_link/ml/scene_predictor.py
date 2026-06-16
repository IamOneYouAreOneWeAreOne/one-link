"""Scene-graph next-frame predictor.

Same architecture shape as voice_predictor but with a different input/
output dimensionality. Input is a 38-dim scene feature vector; output
heads are:
  * next-frame scene regression (MSE)
  * regime classification (5 classes: static, translate, pan, appear, cut)

At inference, the predictive accuracy `p` is derived from the
normalized per-frame MSE and drives video.cl's coherence-prior
throughput multiplier 1/(1-p) exactly as in the voice path.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

from one_link.ml.scene_dataset import FEATURE_DIM, REGIME_NAMES  # noqa: E402


@dataclass
class ScenePredictorConfig:
    feature_dim: int = FEATURE_DIM
    hidden_dim: int = 256
    n_layers: int = 2
    dropout: float = 0.1
    n_regimes: int = len(REGIME_NAMES)


class ScenePredictor(nn.Module):
    def __init__(self, cfg: ScenePredictorConfig):
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
        self.scene_head = nn.Linear(cfg.hidden_dim, cfg.feature_dim)
        self.regime_head = nn.Linear(cfg.hidden_dim, cfg.n_regimes)

    def forward(self, x: torch.Tensor, h0: Optional[torch.Tensor] = None):
        e = self.embed(x)
        y, hn = self.gru(e, h0)
        scene_pred = self.scene_head(y)
        regime_logits = self.regime_head(y)
        return scene_pred, regime_logits, hn


def compute_scene_accuracy(target: np.ndarray, predicted: np.ndarray,
                           sigma: float = 1.0) -> float:
    err = target - predicted
    fd = float(err.shape[-1])
    per_frame_err = np.mean(err ** 2, axis=-1)
    p_per = np.exp(-per_frame_err / (2.0 * sigma * sigma))
    return float(np.mean(p_per))


def _selftest() -> int:
    cfg = ScenePredictorConfig()
    m = ScenePredictor(cfg)
    n_params = sum(p.numel() for p in m.parameters())
    assert n_params > 10_000
    x = torch.randn(3, 30, cfg.feature_dim)
    sp, rl, hn = m(x)
    assert sp.shape == (3, 30, cfg.feature_dim)
    assert rl.shape == (3, 30, cfg.n_regimes)
    print(f"scene_predictor selftest: OK (n_params={n_params:,})")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
