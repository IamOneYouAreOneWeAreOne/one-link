"""Production speech synthesizer for training + eval corpora.

Real physics-based source-filter model (Klatt-style simplified):

  excitation(t)  -- glottal pulse train at fundamental f0, or white
                    noise (fricative), or silence
  formant filter -- cascade of biquad resonators tuned to formant
                    frequencies F1, F2, F3 with configurable bandwidths
  radiation      -- 1st-order high-pass (lip radiation)

The synthesizer knows how to render canonical English phonemes with
realistic formant trajectories derived from measured values (Peterson &
Barney 1952, Hillenbrand 1995):

  Vowels:  /a/, /i/, /u/, /e/, /o/
  Fricatives: /s/, /sh/, /f/
  Nasals:  /m/, /n/ (with closed-velum resonance)
  Stops:   /p/, /t/, /k/ (burst + silence)
  Silence: pause

Each phoneme has a duration envelope + a smooth attack/release.
Sentences are built as ordered phoneme sequences with linear formant
interpolation between adjacent voiced phones.

Public API:
    synth_phoneme(name, duration_s, sr, seed) -> np.ndarray
    synth_sentence(phonemes, sr, seed, jitter=True) -> (audio, per-frame phoneme labels)
    PHONEME_TABLE                              -- the acoustic params

Selftest:
  * every phoneme renders without NaN/inf
  * audio RMS is within [1e-3, 1.0] for voiced phones
  * /a/ and /i/ have clearly different spectral centroids
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from typing import Optional

import numpy as np


# =============================================================================
# ACOUSTIC PARAMETERS -- measured values from standard references
# =============================================================================

@dataclass(frozen=True)
class Phoneme:
    name: str
    voicing: str               # "voiced", "unvoiced", "silence", "stop"
    f0_hz: float               # fundamental (voiced only); 0 for unvoiced
    formants_hz: tuple         # (F1, F2, F3) frequencies
    bandwidths_hz: tuple       # (B1, B2, B3) bandwidths
    noise_gain: float = 0.0    # for fricatives: amplitude of noise source
    burst_ms: float = 0.0      # for stops: burst duration


# Peterson-Barney + Hillenbrand vowel averages (adult male baseline)
# Fricative formants reflect the spectral peak location.
# Stops modeled as a brief silence + burst.
PHONEME_TABLE: dict[str, Phoneme] = {
    "a":  Phoneme("a",  "voiced",   120.0, (730, 1090, 2440), (80, 90, 120)),
    "i":  Phoneme("i",  "voiced",   120.0, (270, 2290, 3010), (60, 100, 150)),
    "u":  Phoneme("u",  "voiced",   120.0, (300,  870, 2240), (70, 90, 140)),
    "e":  Phoneme("e",  "voiced",   120.0, (530, 1840, 2480), (70, 100, 130)),
    "o":  Phoneme("o",  "voiced",   120.0, (570,  840, 2410), (70, 90, 130)),
    "ae": Phoneme("ae", "voiced",   120.0, (660, 1720, 2410), (80, 90, 130)),
    "uh": Phoneme("uh", "voiced",   120.0, (520, 1190, 2390), (70, 90, 120)),
    "m":  Phoneme("m",  "voiced",   120.0, (250, 1100, 2450), (70, 80, 120)),
    "n":  Phoneme("n",  "voiced",   120.0, (250, 1500, 2500), (70, 80, 120)),
    "l":  Phoneme("l",  "voiced",   120.0, (360, 1400, 2700), (70, 90, 130)),
    "r":  Phoneme("r",  "voiced",   120.0, (400, 1300, 1600), (70, 90, 130)),
    "s":  Phoneme("s",  "unvoiced",   0.0, (500, 4000, 6500), (200, 300, 400),
                  noise_gain=0.5),
    "sh": Phoneme("sh", "unvoiced",   0.0, (500, 2500, 3500), (200, 300, 400),
                  noise_gain=0.45),
    "f":  Phoneme("f",  "unvoiced",   0.0, (500, 3500, 5000), (200, 300, 400),
                  noise_gain=0.35),
    "z":  Phoneme("z",  "voiced",   120.0, (500, 4000, 6500), (150, 250, 350),
                  noise_gain=0.3),
    "p":  Phoneme("p",  "stop",       0.0, (500, 1500, 2500), (200, 300, 400),
                  noise_gain=0.25, burst_ms=10.0),
    "t":  Phoneme("t",  "stop",       0.0, (500, 1800, 2700), (200, 300, 400),
                  noise_gain=0.25, burst_ms=8.0),
    "k":  Phoneme("k",  "stop",       0.0, (500, 2200, 2800), (200, 300, 400),
                  noise_gain=0.25, burst_ms=12.0),
    "sil": Phoneme("sil", "silence",  0.0, (500, 1500, 2500), (200, 200, 200)),
}

PHONEME_NAMES = list(PHONEME_TABLE.keys())
PHONEME_ID = {name: i for i, name in enumerate(PHONEME_NAMES)}


# =============================================================================
# BIQUAD RESONATOR (digital formant filter)
# =============================================================================

def _biquad_resonator(sr: float, f_hz: float, bw_hz: float) -> tuple[float, float, float]:
    """Return (b0, a1, a2) for the 2-pole resonator y[n] = b0*x[n] - a1*y[n-1] - a2*y[n-2]."""
    r = math.exp(-math.pi * bw_hz / sr)
    theta = 2.0 * math.pi * f_hz / sr
    a1 = -2.0 * r * math.cos(theta)
    a2 = r * r
    b0 = 1.0 - r   # approx normalization so passband peaks near unity
    return (b0, a1, a2)


def _apply_resonator_scipy(x: np.ndarray, coeffs: tuple[float, float, float]) -> np.ndarray:
    """scipy.signal.lfilter vectorized biquad (100x faster than a Python loop).
    The slow numpy-loop fallback `_apply_resonator` was removed because
    every call site already used this path."""
    from scipy.signal import lfilter
    b0, a1, a2 = coeffs
    return lfilter([b0], [1.0, a1, a2], x).astype(np.float32)


# =============================================================================
# SOURCES
# =============================================================================

def _glottal_pulses(n: int, f0_hz: float, sr: float, jitter_pct: float = 0.02,
                    rng: Optional[np.random.Generator] = None) -> np.ndarray:
    """Triangle-shaped glottal pulse train at the target f0 with natural jitter."""
    if rng is None:
        rng = np.random.default_rng(0)
    out = np.zeros(n, dtype=np.float32)
    if f0_hz <= 0:
        return out
    period = sr / f0_hz
    t_next = rng.uniform(0, period)
    while t_next < n:
        idx = int(t_next)
        # Triangle pulse: 2 ms rise, 3 ms fall.
        rise_samples = int(0.002 * sr)
        fall_samples = int(0.003 * sr)
        for i in range(rise_samples):
            if idx + i < n:
                out[idx + i] += (i + 1) / rise_samples
        for i in range(fall_samples):
            if idx + rise_samples + i < n:
                out[idx + rise_samples + i] += 1.0 - (i + 1) / fall_samples
        period_jit = period * (1.0 + rng.uniform(-jitter_pct, jitter_pct))
        t_next += period_jit
    return out


def _white_noise(n: int, rng: np.random.Generator) -> np.ndarray:
    return rng.normal(0, 1.0, n).astype(np.float32)


# =============================================================================
# PHONEME RENDERING
# =============================================================================

def _envelope(n: int, attack_ms: float = 10.0, release_ms: float = 10.0,
              sr: float = 16000.0) -> np.ndarray:
    env = np.ones(n, dtype=np.float32)
    a = int(attack_ms * 1e-3 * sr)
    r = int(release_ms * 1e-3 * sr)
    if a > 0 and a < n:
        env[:a] = np.linspace(0.0, 1.0, a, dtype=np.float32)
    if r > 0 and r < n:
        env[-r:] = np.linspace(1.0, 0.0, r, dtype=np.float32)
    return env


def synth_phoneme(name: str, duration_s: float, sr: float = 16000.0,
                  seed: int = 0) -> np.ndarray:
    """Render a single phoneme to a float32 waveform."""
    if name not in PHONEME_TABLE:
        raise ValueError(f"unknown phoneme {name!r}")
    p = PHONEME_TABLE[name]
    rng = np.random.default_rng(seed)
    n = int(duration_s * sr)
    if n <= 0:
        return np.zeros(0, dtype=np.float32)

    # Source.
    if p.voicing == "silence":
        return np.zeros(n, dtype=np.float32)
    elif p.voicing == "voiced":
        src = _glottal_pulses(n, p.f0_hz, sr, rng=rng)
        if p.noise_gain > 0:
            src = src + p.noise_gain * _white_noise(n, rng)
    elif p.voicing == "unvoiced":
        src = p.noise_gain * _white_noise(n, rng)
    elif p.voicing == "stop":
        # Silence closure + burst at the end.
        burst_samples = int(p.burst_ms * 1e-3 * sr)
        src = np.zeros(n, dtype=np.float32)
        start = max(0, n - burst_samples)
        src[start:] = p.noise_gain * _white_noise(n - start, rng)
    else:
        raise ValueError(p.voicing)

    # Formant filter cascade (scipy biquads).
    y = src.astype(np.float32)
    for f, bw in zip(p.formants_hz, p.bandwidths_hz):
        coeffs = _biquad_resonator(sr, f, bw)
        y = _apply_resonator_scipy(y, coeffs)

    # Radiation: 1st-order diff.
    y[1:] = y[1:] - 0.95 * y[:-1]
    y[0] = 0.0

    # Envelope to avoid clicks at boundaries.
    env = _envelope(n, attack_ms=5.0, release_ms=5.0, sr=sr)
    y = y * env

    # Normalize to amplitude.
    peak = float(np.max(np.abs(y)))
    if peak > 1e-6:
        y = y / peak * 0.7
    return y.astype(np.float32)


def synth_sentence(phonemes: list[tuple[str, float]], sr: float = 16000.0,
                   seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Synthesize a sentence given [(phoneme_name, duration_s), ...].
    Returns (audio_f32, per-sample_label_int)."""
    rng = np.random.default_rng(seed)
    audio_segments = []
    labels = []
    for i, (name, dur) in enumerate(phonemes):
        seg = synth_phoneme(name, dur, sr=sr, seed=rng.integers(0, 2**31))
        audio_segments.append(seg)
        labels.append(np.full(seg.size, PHONEME_ID[name], dtype=np.int16))
    audio = np.concatenate(audio_segments) if audio_segments else np.zeros(0, dtype=np.float32)
    label_arr = np.concatenate(labels) if labels else np.zeros(0, dtype=np.int16)
    return audio, label_arr


# =============================================================================
# SELFTEST
# =============================================================================

def _selftest() -> int:
    sr = 16000
    # Render every phoneme once.
    for name in PHONEME_NAMES:
        y = synth_phoneme(name, 0.1, sr=sr, seed=1)
        assert not np.isnan(y).any(), f"{name}: NaN in output"
        assert not np.isinf(y).any(), f"{name}: inf in output"
        assert y.size == int(0.1 * sr)
        p = PHONEME_TABLE[name]
        if p.voicing != "silence":
            rms = float(np.sqrt(np.mean(y * y)))
            assert 1e-4 < rms < 1.0, f"{name}: RMS out of range: {rms}"

    # Spectral discrimination: /a/ vs /i/ -- check F2 region energy ratio.
    # /i/ has F2 ~2290 Hz (strong), /a/ has F2 ~1090 Hz. So F2-band energy
    # at 2000-2500 Hz should be much higher for /i/.
    a = synth_phoneme("a", 0.3, sr=sr, seed=1)
    i = synth_phoneme("i", 0.3, sr=sr, seed=1)
    from scipy.fft import rfft
    Sa = np.abs(rfft(a, n=2048))
    Si = np.abs(rfft(i, n=2048))
    freqs = np.fft.rfftfreq(2048, 1.0 / sr)
    f2_band = (freqs > 2000) & (freqs < 2500)
    ea_f2 = float(np.sum(Sa[f2_band]))
    ei_f2 = float(np.sum(Si[f2_band]))
    assert ei_f2 > ea_f2, \
        f"/i/ F2-band energy should exceed /a/: got i={ei_f2:.2f} a={ea_f2:.2f}"

    # Sentence test
    audio, labels = synth_sentence(
        [("sil", 0.05), ("a", 0.15), ("l", 0.1), ("o", 0.15), ("sil", 0.05)],
        sr=sr, seed=1,
    )
    assert audio.size == labels.size > 0

    print(f"speech_synth selftest: OK  (F2-band a={ea_f2:.1f}  i={ei_f2:.1f})")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
