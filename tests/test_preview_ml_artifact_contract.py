"""Truth gates for stable-vs-preview semantic model packaging."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = REPO / "scripts" / "build_binary.py"


def _load_build_module():
    spec = importlib.util.spec_from_file_location("build_binary_claim_truth", BUILD_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_stable_build_is_default_and_preview_requires_explicit_opt_in() -> None:
    module = _load_build_module()
    parser = module.build_arg_parser()
    assert parser.parse_args([]).include_preview_ml is False
    assert parser.parse_args(["--include-preview-ml"]).include_preview_ml is True
    # Preserve compatibility with older automation without reverting the new,
    # fail-safe default.
    assert parser.parse_args(["--no-ml"]).include_preview_ml is False
    help_text = parser.format_help()
    assert "engineering-only" in help_text
    assert "does not enable" in help_text


def test_preview_payload_includes_external_onnx_weights_but_not_torch() -> None:
    module = _load_build_module()
    files = module._collect_preview_model_files(REPO / "assets" / "models")
    relative = {path.relative_to(REPO).as_posix() for path in files}
    assert (
        "assets/models/voice_predictor_v3_librispeech/checkpoint.onnx.data"
        in relative
    )
    assert {
        "assets/models/voice_predictor_v3_librispeech/checkpoint.onnx",
        "assets/models/voice_predictor_v3_librispeech/config.json",
        "assets/models/scene_predictor_v1/checkpoint.onnx",
        "assets/models/scene_predictor_v1/config.json",
    } <= relative
    assert not any(path.endswith(".pt") for path in relative)


def test_preview_payload_validation_fails_closed_on_incomplete_model(
    tmp_path: Path,
) -> None:
    module = _load_build_module()
    for model_name in module._PREVIEW_MODEL_DIRS:
        model_dir = tmp_path / model_name
        model_dir.mkdir(parents=True)
        (model_dir / "config.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="incomplete"):
        module._collect_preview_model_files(tmp_path)


def test_preview_runtime_requires_named_locked_extra(monkeypatch) -> None:
    module = _load_build_module()

    def fail_import(name: str):
        if name == "onnxruntime":
            raise ImportError("not installed")
        return object()

    monkeypatch.setattr(module.importlib, "import_module", fail_import)
    with pytest.raises(RuntimeError, match="preview-ml"):
        module._validate_preview_runtime([])


def test_preview_model_resolver_prefers_frozen_bundle_without_cwd_dependency(
    tmp_path: Path, monkeypatch,
) -> None:
    from one_link.ml import preview_model_dir

    model = (
        tmp_path
        / "assets"
        / "models"
        / "voice_predictor_v3_librispeech"
    )
    model.mkdir(parents=True)
    (model / "checkpoint.onnx").write_bytes(b"onnx")
    (model / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert preview_model_dir("voice_predictor_v3_librispeech") == model
    with pytest.raises(ValueError, match="unknown preview model"):
        preview_model_dir("attacker-controlled-path")


def test_opt_in_onnx_codecs_initialize_and_execute_without_torch(
    monkeypatch,
) -> None:
    import builtins

    np = pytest.importorskip("numpy")
    pytest.importorskip("scipy")
    pytest.importorskip("onnxruntime")
    from one_link.ml import preview_model_dir
    from one_link.semantic_scene_codec import (
        SemanticSceneDecoder,
        SemanticSceneEncoder,
    )
    from one_link.semantic_voice_codec import (
        SemanticVoiceDecoder,
        SemanticVoiceEncoder,
    )

    real_import = builtins.__import__

    def no_torch_import(name, *args, **kwargs):
        if name == "torch" or name.startswith("torch."):
            raise ImportError("torch deliberately unavailable in preview artifact")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_torch_import)

    voice_dir = preview_model_dir("voice_predictor_v3_librispeech")
    voice_encoder = SemanticVoiceEncoder(voice_dir)
    voice_frames = voice_encoder.encode_pcm(np.zeros(1600, dtype=np.int16))
    assert len(voice_frames) == 1
    voice_pcm = SemanticVoiceDecoder().decode_frames(voice_frames)
    assert voice_pcm.shape == (1600,)
    assert np.isfinite(voice_pcm).all()

    scene_dir = preview_model_dir("scene_predictor_v1")
    scene_encoder = SemanticSceneEncoder(scene_dir)
    scene_frames = scene_encoder.encode_features(
        np.zeros((2, 38), dtype=np.float32)
    )
    decoded, regimes = SemanticSceneDecoder(scene_dir).decode_frames(scene_frames)
    assert decoded.shape == (2, 38)
    assert len(regimes) == 2
    assert np.isfinite(decoded).all()


def test_release_workflow_never_publishes_preview_ml_as_stable() -> None:
    workflow = (REPO / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "--include-preview-ml" not in workflow
    assert "--extra ml-runtime" not in workflow
    assert "--extra preview-ml" not in workflow
    assert "preview-ml = [" in pyproject
    assert "ml-runtime = [" not in pyproject
