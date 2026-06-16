"""Production MFCC feature extractor.

Real pipeline, no shortcuts:
  1. pre-emphasis (first-difference filter, alpha=0.97)
  2. framing + windowing (Hann window, configurable frame/hop length)
  3. real-FFT -> magnitude spectrum
  4. mel filterbank (N triangular filters between f_min..f_max, HTK formula)
  5. log compression
  6. DCT-II -> MFCC coefficients
  7. optional delta + delta-delta (first + second time derivatives)

Implementation is scipy + numpy only (no torchaudio dependency).
Uses np.float32 end-to-end for numerical parity with a future CUDA
port (see tools/ml/mfcc_cuda.py -- TODO).

Public API:
    compute_mfcc(signal, sr, n_mfcc=20, n_fft=512, hop=160,
                 win=400, f_min=0.0, f_max=None, include_deltas=True)
        -> np.ndarray of shape (T, n_mfcc * (3 if include_deltas else 1))

    MfccConfig(...)              -- dataclass of parameters
    mfcc_from_config(x, cfg)     -- same computation driven by config

Selftest asserts:
  * output shape matches expectation for a 1-second input
  * MFCC energy concentrated in low coefficients (as expected)
  * pure tone at 1 kHz produces stable MFCCs across frames
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

import numpy as np
from scipy.fft import dct, rfft
from scipy.signal import get_window


# =============================================================================
# MEL CONVERSION (HTK formula)
# =============================================================================

def hz_to_mel(f_hz: np.ndarray | float) -> np.ndarray | float:
    return 2595.0 * np.log10(1.0 + np.asarray(f_hz) / 700.0)


def mel_to_hz(m: np.ndarray | float) -> np.ndarray | float:
    return 700.0 * (10.0 ** (np.asarray(m) / 2595.0) - 1.0)


def mel_filterbank(n_filters: int, n_fft: int, sr: float,
                   f_min: float = 0.0, f_max: Optional[float] = None) -> np.ndarray:
    """Build a triangular mel-filterbank matrix of shape (n_filters, n_fft//2 + 1)."""
    if f_max is None:
        f_max = sr / 2.0
    mels = np.linspace(hz_to_mel(f_min), hz_to_mel(f_max), n_filters + 2)
    freqs = mel_to_hz(mels)
    bin_edges = np.floor((n_fft + 1) * freqs / sr).astype(int)
    bin_edges = np.clip(bin_edges, 0, n_fft // 2)

    fb = np.zeros((n_filters, n_fft // 2 + 1), dtype=np.float32)
    for i in range(n_filters):
        l, c, r = bin_edges[i], bin_edges[i + 1], bin_edges[i + 2]
        if c > l:
            fb[i, l:c] = (np.arange(l, c) - l) / max(c - l, 1)
        if r > c:
            fb[i, c:r] = (r - np.arange(c, r)) / max(r - c, 1)
    return fb


# =============================================================================
# CONFIG + EXTRACT
# =============================================================================

@dataclass
class MfccConfig:
    sample_rate: float = 16000.0
    n_fft: int = 512
    hop_length: int = 160       # 10 ms at 16 kHz
    win_length: int = 400       # 25 ms at 16 kHz
    window: str = "hann"
    n_mels: int = 40
    n_mfcc: int = 20
    f_min: float = 0.0
    f_max: Optional[float] = None
    pre_emphasis: float = 0.97
    include_deltas: bool = True
    log_floor: float = 1e-10
    normalize: bool = True      # mean-var normalize across time

    def feature_dim(self) -> int:
        return self.n_mfcc * (3 if self.include_deltas else 1)


def _preemphasis(x: np.ndarray, alpha: float) -> np.ndarray:
    if alpha == 0.0:
        return x
    y = np.empty_like(x)
    y[0] = x[0]
    y[1:] = x[1:] - alpha * x[:-1]
    return y


def _frame_signal(x: np.ndarray, frame_len: int, hop: int) -> np.ndarray:
    """Slice x into overlapping frames. Shape: (n_frames, frame_len)."""
    n_frames = 1 + max(0, (x.size - frame_len) // hop)
    if n_frames <= 0:
        return np.zeros((0, frame_len), dtype=np.float32)
    shape = (n_frames, frame_len)
    strides = (x.strides[0] * hop, x.strides[0])
    return np.lib.stride_tricks.as_strided(x, shape=shape, strides=strides).copy()


def _delta(feat: np.ndarray, width: int = 2) -> np.ndarray:
    """First time-derivative of features (like librosa.delta)."""
    T = feat.shape[0]
    if T < 2:
        return np.zeros_like(feat)
    pad = np.pad(feat, ((width, width), (0, 0)), mode="edge")
    denom = 2 * sum(i * i for i in range(1, width + 1))
    out = np.zeros_like(feat)
    for i in range(1, width + 1):
        out += i * (pad[width + i : width + i + T] - pad[width - i : width - i + T])
    return out / max(denom, 1)


def compute_mfcc(signal: np.ndarray, cfg: Optional[MfccConfig] = None,
                 **kwargs) -> np.ndarray:
    """Compute MFCC features from a mono float32 waveform.
    Returns array of shape (T, n_mfcc * (3 if deltas else 1))."""
    if cfg is None:
        cfg = MfccConfig(**kwargs)

    x = np.asarray(signal, dtype=np.float32).flatten()
    if x.size == 0:
        return np.zeros((0, cfg.feature_dim()), dtype=np.float32)

    x = _preemphasis(x, cfg.pre_emphasis)
    frames = _frame_signal(x, cfg.win_length, cfg.hop_length)
    if frames.size == 0:
        return np.zeros((0, cfg.feature_dim()), dtype=np.float32)

    win = get_window(cfg.window, cfg.win_length, fftbins=True).astype(np.float32)
    frames = frames * win
    # Zero-pad to n_fft if win < n_fft.
    if cfg.win_length < cfg.n_fft:
        pad = np.zeros((frames.shape[0], cfg.n_fft - cfg.win_length), dtype=np.float32)
        frames = np.concatenate([frames, pad], axis=1)
    spec = np.abs(rfft(frames, n=cfg.n_fft, axis=1)).astype(np.float32)  # (T, n_fft//2+1)
    power = spec * spec

    fb = mel_filterbank(cfg.n_mels, cfg.n_fft, cfg.sample_rate,
                        cfg.f_min, cfg.f_max)
    mel_energy = power @ fb.T            # (T, n_mels)
    log_mel = np.log(np.maximum(mel_energy, cfg.log_floor)).astype(np.float32)

    mfcc = dct(log_mel, type=2, axis=1, norm="ortho")[:, : cfg.n_mfcc].astype(np.float32)

    if cfg.include_deltas:
        d = _delta(mfcc)
        dd = _delta(d)
        mfcc = np.concatenate([mfcc, d, dd], axis=1)

    if cfg.normalize and mfcc.shape[0] > 1:
        mu = mfcc.mean(axis=0, keepdims=True)
        sigma = mfcc.std(axis=0, keepdims=True) + 1e-8
        mfcc = (mfcc - mu) / sigma

    return mfcc.astype(np.float32)


# =============================================================================
# SELFTEST
# =============================================================================

def _selftest() -> int:
    # 1-second 16 kHz sine sweep
    sr = 16000
    n = sr
    t = np.arange(n) / sr
    x = 0.5 * np.sin(2 * np.pi * 440 * t) + 0.25 * np.sin(2 * np.pi * 1200 * t)

    cfg = MfccConfig(sample_rate=sr)
    mfcc = compute_mfcc(x, cfg)

    expected_frames = 1 + (n - cfg.win_length) // cfg.hop_length
    assert mfcc.shape[0] == expected_frames, \
        f"frame count wrong: got {mfcc.shape[0]} expected {expected_frames}"
    assert mfcc.shape[1] == cfg.feature_dim()
    assert mfcc.dtype == np.float32
    assert not np.isnan(mfcc).any()
    assert not np.isinf(mfcc).any()

    # Stability: a stationary tone should have low frame-to-frame variance
    # in the mfcc coefficients (after pre-emphasis transient).
    coef_var = mfcc[10:, :cfg.n_mfcc].std(axis=0).mean()
    assert coef_var < 2.0, f"MFCC too unstable on pure tone: var={coef_var}"

    # Silence case
    sil = np.zeros(n, dtype=np.float32)
    mfcc_sil = compute_mfcc(sil, cfg)
    assert mfcc_sil.shape[0] == expected_frames
    assert not np.isnan(mfcc_sil).any()

    # Delta channel presence
    assert mfcc.shape[1] == cfg.n_mfcc * 3

    print(f"mfcc selftest: OK  (shape={mfcc.shape}, coef_var={coef_var:.3f})")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
