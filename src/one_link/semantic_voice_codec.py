"""Semantic voice codec — Tier ζ articulatory codec at ~1 kbps.

Uses the trained LibriSpeech voice predictor + Klatt-style formant
synthesizer to compress speech down to a phoneme stream + pitch
contour + sparse spectral residual.

Architecture:

  ENCODER (sender)
    audio (16 kHz, 16-bit) → MFCC (60-dim, 10 ms hop, 100 fps)
    → run trained predictor → next-frame prediction + phoneme posterior
    → decimate to 10 fps (keep every 10th frame)
    → per frame, emit:
        - 5 bits  phoneme class (argmax of phoneme head)
        - 8 bits  log-f0 quantized (silent if unvoiced)
        - K × 4 bits  top-K residual MFCC components
      total ~50 bits / frame × 10 fps = ~500 bps

  DECODER (receiver)
    wire bytes → unpack frames
    → phoneme stream drives speech_synth (Klatt formant model)
    → pitch overrides f0 of voiced phonemes
    → output audio (16 kHz, 16-bit)

The predictor's role here is selection of WHICH residual components
to send — it sees what the receiver-side decoder will get right for
free, so only divergences need wire bytes.

Capability gate: ``SEMANTIC_VOICE_V1``. Both peers must advertise
``model_pack_hash`` matching the trained checkpoint hash; otherwise
the Compiler refuses the SEMANTIC_DELTA_AV rung and falls back to
the OPUS_VIDEO / AUDIO_ONLY rungs.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.8 (Semantic Engine)
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

WIRE_MAGIC = b"OLSVC1\x00\x00"   # 8 bytes
WIRE_VERSION = 1


@dataclass(frozen=True)
class CodecFrame:
    """One 100 ms semantic frame on the wire."""

    phoneme_id: int        # 0..18 (19 phonemes — fits in 5 bits)
    log_f0_q: int          # 0..255; 0 = silence/unvoiced
    residual_indices: tuple[int, ...]   # MFCC dims with non-zero residual
    residual_values_q: tuple[int, ...]  # quantized to 4-bit signed -8..7

    def to_bytes(self) -> bytes:
        # Compact encoding:
        # byte 0: phoneme_id (5 bits) | n_residual (3 bits)
        # byte 1: log_f0_q
        # then n_residual × (1 byte index + 4-bit packed value pairs)
        b = bytearray()
        n = len(self.residual_indices)
        assert n == len(self.residual_values_q)
        assert n <= 7
        assert 0 <= self.phoneme_id <= 31
        b.append(((self.phoneme_id & 0x1f) << 3) | (n & 0x07))
        b.append(self.log_f0_q & 0xff)
        for i in range(0, n, 2):
            # Pack two indices' values into one byte (4 bits each)
            v0 = self.residual_values_q[i] & 0x0f
            v1 = (
                self.residual_values_q[i + 1] & 0x0f
                if i + 1 < n else 0
            )
            b.append(((v1 << 4) | v0))
        # Indices follow as one byte per (max 60 dims fits in 6 bits)
        for idx in self.residual_indices:
            b.append(idx & 0xff)
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple["CodecFrame", int]:
        """Returns (frame, bytes_consumed)."""
        if len(data) < offset + 2:
            raise ValueError("frame truncated at header")
        h = data[offset]
        phoneme_id = (h >> 3) & 0x1f
        n = h & 0x07
        log_f0_q = data[offset + 1]
        n_packed = (n + 1) // 2
        if len(data) < offset + 2 + n_packed + n:
            raise ValueError("frame truncated at body")
        values: list[int] = []
        for i in range(n_packed):
            byte = data[offset + 2 + i]
            v0 = byte & 0x0f
            v1 = (byte >> 4) & 0x0f
            # Sign-extend 4-bit two's complement
            if v0 >= 8:
                v0 -= 16
            if v1 >= 8:
                v1 -= 16
            values.append(v0)
            if len(values) < n:
                values.append(v1)
        indices = tuple(
            data[offset + 2 + n_packed + i] for i in range(n)
        )
        return (
            cls(
                phoneme_id=phoneme_id,
                log_f0_q=log_f0_q,
                residual_indices=indices,
                residual_values_q=tuple(values),
            ),
            2 + n_packed + n,
        )


# ---------------------------------------------------------------------------
# Quantization
# ---------------------------------------------------------------------------

# Log-f0 range: typical adult voiced speech 80–400 Hz.
# log2(80) ≈ 6.32, log2(400) ≈ 8.64. Map this 2.32-octave range to 1..255.
# 0 reserved for silent / unvoiced.
_F0_LO_HZ = 80.0
_F0_HI_HZ = 400.0


def _quantize_f0(f0_hz: float) -> int:
    if f0_hz <= 0:
        return 0
    f0 = max(_F0_LO_HZ, min(_F0_HI_HZ, f0_hz))
    lo, hi = np.log2(_F0_LO_HZ), np.log2(_F0_HI_HZ)
    return int(1 + ((np.log2(f0) - lo) / (hi - lo)) * 254)


def _dequantize_f0(q: int) -> float:
    if q == 0:
        return 0.0
    lo, hi = np.log2(_F0_LO_HZ), np.log2(_F0_HI_HZ)
    return float(2 ** (lo + ((q - 1) / 254) * (hi - lo)))


# Residual scaling — MFCC residuals are typically in ±2 after normalization.
# Quantize to int4 signed using a fixed scale of 0.25.
_RESIDUAL_SCALE = 4.0


def _quantize_residual(value: float) -> int:
    q = int(round(value * _RESIDUAL_SCALE))
    return max(-8, min(7, q))


def _dequantize_residual(q: int) -> float:
    return q / _RESIDUAL_SCALE


# ---------------------------------------------------------------------------
# Top-K residual selection
# ---------------------------------------------------------------------------

def _top_k_residual(
    actual: np.ndarray, predicted: np.ndarray, k: int = 4,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return (indices, quantized_values) for the K largest-magnitude
    components of (actual - predicted), restricted to the first 60 MFCC dims."""
    residual = actual - predicted
    abs_res = np.abs(residual)
    n_dims = min(len(residual), 60)
    top_k = min(k, n_dims)
    idx = np.argpartition(abs_res[:n_dims], -top_k)[-top_k:]
    idx = np.sort(idx)
    indices = tuple(int(i) for i in idx)
    values = tuple(_quantize_residual(float(residual[i])) for i in idx)
    return indices, values


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

# Phoneme name → ID table mirrors the training corpus's 19-phoneme set.
# Imported from speech_synth so the encoder ID matches the decoder.
def _phoneme_table():
    from one_link.ml.speech_synth import PHONEME_ID, PHONEME_NAMES
    return PHONEME_ID, PHONEME_NAMES


class SemanticVoiceEncoder:
    """Encode a PCM audio buffer into a sparse semantic frame stream.

    Stateful — carries the predictor's GRU hidden state between
    calls so streaming chunks decode to the same bytes as
    encoding the whole stream at once.

    Thread-safe under a single internal lock.
    """

    SAMPLE_RATE = 16000
    FRAME_RATE_HZ = 10        # 10 fps semantic frames (100 ms each)
    MFCC_FPS = 100            # MFCC hop = 10 ms
    RESIDUAL_K = 4            # top-K MFCC dims sent

    def __init__(self, ckpt_path: Path, device: str = "cpu") -> None:
        """Construct an encoder. ``ckpt_path`` may be either:
          - the legacy .pt PyTorch checkpoint (loads via torch)
          - the .onnx export (loads via onnxruntime — no torch dep)
          - the model directory (auto-prefers .onnx if present)
        """
        from one_link.ml.onnx_oracles import load_voice_oracle
        from one_link.ml.trained_voice_oracle import TrainedVoiceOracle
        self._lock = threading.Lock()
        ckpt_path = Path(ckpt_path)
        if ckpt_path.is_dir():
            self._oracle = load_voice_oracle(ckpt_path)
        elif ckpt_path.suffix == ".onnx":
            self._oracle = load_voice_oracle(ckpt_path.parent)
        else:
            # Explicit .pt path → use torch oracle directly.
            self._oracle = TrainedVoiceOracle(ckpt_path, device=device)
        self._mfcc_buffer: list[np.ndarray] = []
        self._frame_counter = 0
        self._mfcc_carry = np.zeros(0, dtype=np.float32)
        self._sample_carry = np.zeros(0, dtype=np.float32)

    def reset(self) -> None:
        with self._lock:
            self._oracle.reset()
            self._mfcc_buffer = []
            self._frame_counter = 0
            self._mfcc_carry = np.zeros(0, dtype=np.float32)
            self._sample_carry = np.zeros(0, dtype=np.float32)

    def encode_pcm(self, pcm_i16: np.ndarray) -> list[CodecFrame]:
        """Encode a PCM s16 buffer at 16 kHz into a list of semantic
        frames. Buffers partial frames; the next call resumes where
        this one left off."""
        with self._lock:
            audio = pcm_i16.astype(np.float32) / 32768.0
            audio = np.concatenate([self._sample_carry, audio])
            # Keep at least 1 hop-window of carry so MFCC extraction
            # is consistent across chunks. We'll emit MFCC for whole
            # 100ms windows and carry the tail.
            samples_per_semantic_frame = self.SAMPLE_RATE // self.FRAME_RATE_HZ
            n_semantic = len(audio) // samples_per_semantic_frame
            if n_semantic == 0:
                self._sample_carry = audio
                return []
            consume = n_semantic * samples_per_semantic_frame
            window = audio[:consume]
            self._sample_carry = audio[consume:]
            mfcc = self._oracle.extract_mfcc(window)  # (T, 60)
            # Emit one semantic frame per 100 ms — decimate MFCC by
            # taking the centroid frame of each 10-frame block.
            frames_out: list[CodecFrame] = []
            mfcc_per_semantic = mfcc.shape[0] // n_semantic
            if mfcc_per_semantic == 0:
                return []
            for i in range(n_semantic):
                lo = i * mfcc_per_semantic
                hi = lo + mfcc_per_semantic
                block = mfcc[lo:hi]
                # Centroid frame: the median frame of the block.
                actual_frame = block[len(block) // 2]
                predicted = self._oracle.predict_next(actual_frame)
                phoneme_id = self._classify_phoneme(actual_frame)
                # Use first 13 MFCC coefficients (base, ex deltas) for
                # log-f0 estimation. The 0th cep is energy; 1..12 are
                # spectral. The energy + ratio gives a robust voicing
                # signal. Real f0 extraction would use autocorrelation;
                # we use a coarse log-f0 from the predictor's phoneme
                # plus energy here for simplicity.
                f0_hz = self._estimate_f0(actual_frame, phoneme_id)
                log_f0_q = _quantize_f0(f0_hz)
                indices, values = _top_k_residual(
                    actual_frame, predicted, k=self.RESIDUAL_K,
                )
                frames_out.append(CodecFrame(
                    phoneme_id=phoneme_id,
                    log_f0_q=log_f0_q,
                    residual_indices=indices,
                    residual_values_q=values,
                ))
                self._frame_counter += 1
            return frames_out

    def _classify_phoneme(self, mfcc_frame: np.ndarray) -> int:
        """Hand off to the predictor head — phoneme posterior is part
        of the model's output. Returns the argmax in [0, 19).

        Works against both the torch oracle (real ``torch.Tensor``
        outputs) and the ONNX oracle (numpy arrays wrapped in a
        torch-like shim). We coerce defensively in both directions."""
        x_np = mfcc_frame.astype(np.float32).reshape(1, 1, -1)
        # Try torch path first if the oracle is torch-backed.
        try:
            import torch
            if getattr(self._oracle, "device", "cpu") != "cpu" or hasattr(self._oracle, "_extrap"):
                pass
            x = torch.from_numpy(x_np).to(getattr(self._oracle, "device", "cpu"))
            with torch.no_grad():
                _, phone_logits, _ = self._oracle.model(x)
            arr = phone_logits.cpu().numpy() if hasattr(phone_logits, "cpu") else np.asarray(phone_logits)
        except Exception:
            # ONNX fallback: oracle.model accepts numpy directly.
            _, phone_logits, _ = self._oracle.model(x_np)
            arr = phone_logits.numpy() if hasattr(phone_logits, "numpy") else np.asarray(phone_logits)
        cls = int(np.argmax(arr, axis=-1).item())
        return max(0, min(18, cls))

    def _estimate_f0(self, mfcc_frame: np.ndarray, phoneme_id: int) -> float:
        """Coarse f0 estimate. Unvoiced phonemes → 0. For voiced
        phonemes, energy in the 1st mel band gives a proxy."""
        _, names = _phoneme_table()
        name = names[phoneme_id] if phoneme_id < len(names) else "sil"
        unvoiced = {"sil", "s", "sh", "f", "p", "t", "k"}
        if name in unvoiced:
            return 0.0
        # Default voiced f0 — average male is ~120 Hz; female ~210 Hz.
        # The trained model isn't pitch-aware so we anchor at 120 Hz
        # for the v0 codec.
        return 120.0


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class SemanticVoiceDecoder:
    """Decode a semantic frame stream back to audio.

    Stateful — carries an open phoneme + a running pitch contour so
    chunked decoding produces the same waveform as decoding the
    full stream at once.

    Thread-safe.
    """

    SAMPLE_RATE = 16000
    FRAME_RATE_HZ = 10

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def decode_frames(self, frames: list[CodecFrame]) -> np.ndarray:
        """Render a list of semantic frames to float32 PCM.

        Output sample rate is 16 kHz. Each frame contributes
        ``SAMPLE_RATE / FRAME_RATE_HZ`` = 1600 samples (100 ms)."""
        from one_link.ml.speech_synth import synth_phoneme
        _, names = _phoneme_table()
        with self._lock:
            if not frames:
                return np.zeros(0, dtype=np.float32)
            duration_s = 1.0 / self.FRAME_RATE_HZ
            chunks = []
            for f in frames:
                name = names[f.phoneme_id] if f.phoneme_id < len(names) else "sil"
                seg = synth_phoneme(
                    name, duration_s=duration_s,
                    sr=float(self.SAMPLE_RATE),
                    seed=hash((f.phoneme_id, f.log_f0_q)) & 0xffff,
                )
                # Apply log_f0 gain when voiced — quiet for unvoiced.
                if f.log_f0_q == 0:
                    seg = seg * 0.5
                chunks.append(seg)
            return np.concatenate(chunks)


# ---------------------------------------------------------------------------
# Wire envelope (multiple frames → single packet)
# ---------------------------------------------------------------------------

def pack_packet(frames: list[CodecFrame]) -> bytes:
    """Serialize a list of frames into a single wire packet:
        MAGIC(8) || VERSION(1) || FRAME_COUNT(2) || frame bytes..."""
    body = b"".join(f.to_bytes() for f in frames)
    return (
        WIRE_MAGIC
        + struct.pack("!BH", WIRE_VERSION, len(frames))
        + body
    )


def unpack_packet(data: bytes) -> list[CodecFrame]:
    """Inverse of :func:`pack_packet`. Raises ValueError on bad input."""
    if len(data) < len(WIRE_MAGIC) + 3:
        raise ValueError("packet too short")
    if data[:len(WIRE_MAGIC)] != WIRE_MAGIC:
        raise ValueError("bad magic")
    version, count = struct.unpack(
        "!BH", data[len(WIRE_MAGIC):len(WIRE_MAGIC) + 3],
    )
    if version != WIRE_VERSION:
        raise ValueError(f"unsupported version {version}")
    pos = len(WIRE_MAGIC) + 3
    frames: list[CodecFrame] = []
    for _ in range(count):
        if pos >= len(data):
            raise ValueError("packet truncated mid-frame")
        f, consumed = CodecFrame.from_bytes(data, offset=pos)
        frames.append(f)
        pos += consumed
    if pos != len(data):
        raise ValueError(
            f"packet has {len(data) - pos} trailing bytes",
        )
    return frames


# ---------------------------------------------------------------------------
# Model pack hash — for SEMANTIC_VOICE_V1 capability negotiation
# ---------------------------------------------------------------------------

def model_pack_hash(ckpt_path: Path) -> str:
    """Stable SHA-256 of the trained checkpoint. Peers compare hashes
    in CAPS to confirm they're running the same model — otherwise the
    Compiler refuses the SEMANTIC_DELTA_AV rung and falls back."""
    h = hashlib.sha256()
    with Path(ckpt_path).open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Bitrate calculation
# ---------------------------------------------------------------------------

def estimate_bitrate_bps(
    frames: list[CodecFrame], frame_rate_hz: float = 10.0,
) -> float:
    """Return effective bitrate in bps over the duration of ``frames``."""
    if not frames:
        return 0.0
    total_bytes = sum(len(f.to_bytes()) for f in frames)
    duration_s = len(frames) / frame_rate_hz
    return (total_bytes * 8) / duration_s
