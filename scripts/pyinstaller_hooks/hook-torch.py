"""PyInstaller hook for torch: strip all binary and datafile
collection. Stable builds omit semantic ML entirely; explicit preview builds
use CPU-only ONNX Runtime. Torch's CUDA DLLs alone add ~1.6 GB to the bundle.

Even with ``--exclude-module torch``, PyInstaller's binary-dep
analyzer can still discover torch/lib/*.dll via transitive deps
(numba / cupy / onnxruntime-gpu / scipy). This hook forces empty
``binaries`` and ``datas`` for torch and its CUDA satellites."""

binaries: list[tuple[str, str]] = []
datas: list[tuple[str, str]] = []
hiddenimports: list[str] = []
excludedimports = [
    "torch",
    "torch.cuda",
    "torch.distributed",
    "torch.backends",
    "torch._dynamo",
    "torch._inductor",
    "torchvision",
    "torchaudio",
]
