from __future__ import annotations

from setuptools import setup

try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except Exception:  # pragma: no cover - only used during package build
    _bdist_wheel = None


if _bdist_wheel is not None:
    class bdist_wheel(_bdist_wheel):
        def finalize_options(self) -> None:
            super().finalize_options()
            # The wheel can carry a platform-native CDC DLL/.so/.dylib.
            # Mark it non-pure so installers do not treat it as universal.
            self.root_is_pure = False

        def get_tag(self):
            _py, _abi, plat = super().get_tag()
            # The bundled scanner uses ctypes and the stable C ABI; it is
            # platform-specific but not CPython-minor-version-specific.
            return "py3", "none", plat

    setup(cmdclass={"bdist_wheel": bdist_wheel})
else:
    setup()
