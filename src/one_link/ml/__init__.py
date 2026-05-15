"""Vendored ML stack for One Link semantic codecs (Tier ζ+).

Sources: harvested from `OneField Mesh/tools/ml/` (Apr 2026), where
the models were trained on LibriSpeech. The voice predictor here is
the v3_librispeech checkpoint — 88% predictive accuracy on
validation, 97% on simple Klatt-synth utterances.

Modules:
  - mfcc: production MFCC extractor (scipy + numpy, no torchaudio)
  - voice_predictor: 60-dim MFCC + 19-phoneme GRU predictor
  - trained_voice_oracle: stateful online inference wrapper
  - speech_synth: Klatt-style formant synthesizer for the receiver
    reconstruction path

The trained checkpoint lives at
``assets/models/voice_predictor_v3_librispeech/checkpoint.pt``.
"""
