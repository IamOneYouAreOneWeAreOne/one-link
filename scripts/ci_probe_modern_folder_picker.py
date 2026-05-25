"""CI smoke: verify the modern Windows folder picker can initialize.

This script does NOT show a dialog (CI runners may not have an
interactive display session). It probes ONLY whether CoCreateInstance
succeeds against at least one of the two FileOpenDialog CLSIDs the
production picker tries:

  - Classic: DC1C5A9C-E88A-4ADE-A5A1-60F82A20AEF7
  - Broker:  3217B1B1-5DC3-4590-9C62-EF9E2DF1C25D

If BOTH return REGDB_E_CLASSNOTREG on the CI runner's Windows build,
the production daemon would silently fall through to the legacy
WinForms FolderBrowserDialog - the 90s-looking dialog the user
explicitly rejected. This script makes that regression a CI failure
so we learn about it before users do.

Run via the windows_native_picker_smoke job in
.github/workflows/full_suite_and_e2e.yml.

Exits 0 on success, non-zero on failure. Prints which CLSID worked.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, byref, c_void_p
from ctypes import wintypes


if sys.platform != "win32":
    print(f"not windows ({sys.platform}); skipping")
    sys.exit(0)


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _g(s: str) -> _GUID:
    s = s.replace("-", "")
    g = _GUID()
    g.Data1 = int(s[0:8], 16)
    g.Data2 = int(s[8:12], 16)
    g.Data3 = int(s[12:16], 16)
    for i in range(8):
        g.Data4[i] = int(s[16 + 2 * i: 18 + 2 * i], 16)
    return g


CLSID_classic = _g("DC1C5A9C-E88A-4ADE-A5A1-60F82A20AEF7")
CLSID_broker = _g("3217B1B1-5DC3-4590-9C62-EF9E2DF1C25D")
IID_IFileOpenDialog = _g("D57C7288-D4AD-4768-BE02-9D969532D960")

CLSCTX_INPROC_SERVER = 0x1
COINIT_APARTMENTTHREADED = 0x2
COINIT_DISABLE_OLE1DDE = 0x4
S_OK = 0
S_FALSE = 1
RPC_E_CHANGED_MODE = -2147417850

ole32 = ctypes.WinDLL("ole32")
ole32.CoInitializeEx.restype = ctypes.c_long
ole32.CoInitializeEx.argtypes = [c_void_p, wintypes.DWORD]
ole32.CoCreateInstance.restype = ctypes.c_long
ole32.CoCreateInstance.argtypes = [
    POINTER(_GUID), c_void_p, wintypes.DWORD,
    POINTER(_GUID), POINTER(c_void_p),
]
ole32.CoUninitialize.restype = None


def _try_clsid(name: str, clsid: _GUID) -> int:
    """Returns the HRESULT from CoCreateInstance. 0 = success."""
    ppv = c_void_p()
    hr = ole32.CoCreateInstance(
        byref(clsid), None, CLSCTX_INPROC_SERVER,
        byref(IID_IFileOpenDialog), byref(ppv),
    )
    if hr == S_OK and ppv.value:
        # Release immediately - we don't need the object, just the
        # confirmation that CoCreateInstance returned a valid one.
        vtbl = ctypes.cast(ppv, POINTER(POINTER(c_void_p))).contents
        ReleaseFN = ctypes.WINFUNCTYPE(wintypes.ULONG, c_void_p)
        Release = ReleaseFN(vtbl[2])
        Release(ppv)
    return hr


def main() -> int:
    hr = ole32.CoInitializeEx(
        None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
    )
    if hr not in (S_OK, S_FALSE) and hr != RPC_E_CHANGED_MODE:
        print(f"FATAL: CoInitializeEx failed: 0x{hr & 0xFFFFFFFF:08X}")
        return 1
    try:
        hr_classic = _try_clsid("classic", CLSID_classic)
        if hr_classic == S_OK:
            print("OK: classic CLSID_FileOpenDialog initialized")
            return 0
        print(
            f"classic CLSID failed: 0x{hr_classic & 0xFFFFFFFF:08X} "
            "(REGDB_E_CLASSNOTREG = 0x80040154 = not registered)"
        )
        hr_broker = _try_clsid("broker", CLSID_broker)
        if hr_broker == S_OK:
            print("OK: BrokerFileOpenDialog initialized (fallback path)")
            return 0
        print(
            f"broker CLSID also failed: 0x{hr_broker & 0xFFFFFFFF:08X}\n"
            "FATAL: neither modern picker CLSID is registered on this "
            "Windows build. The production daemon would silently fall "
            "through to the legacy WinForms FolderBrowserDialog (the "
            "90s-looking dialog the v0.21.x picker fix replaced)."
        )
        return 1
    finally:
        ole32.CoUninitialize()


if __name__ == "__main__":
    sys.exit(main())
