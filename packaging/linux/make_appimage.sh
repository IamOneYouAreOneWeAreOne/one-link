#!/usr/bin/env bash
# Build a Linux AppImage from the PyInstaller bundle.
#
# AppImage is a portable Linux install format: one executable file,
# built separately for x86_64 and aarch64. Compatibility still depends
# on the kernel/glibc baseline of the PyInstaller payload; packaging as
# an AppImage is not a claim that every Linux distribution is supported.
#
#   .deb       — Debian + Ubuntu only, needs apt + sudo
#   .rpm       — Fedora + RHEL + openSUSE only
#   Flatpak    — needs Flatpak runtime pre-installed
#   Snap       — Ubuntu-centric, snapd dependency
#   AppImage   — single file, no root install; supported hosts can run it.
#
# Design contract — same "for the people, not corp" stance as the
# Windows installer + macOS .dmg:
#
#   * No root required. AppImage runs from the user's Downloads or
#     ~/Applications folder.
#   * No package-manager integration (the user can drop a .desktop
#     file via the in-app autostart feature; the AppImage doesn't
#     mutate the system).
#   * No telemetry or update-framework injection is added by this
#     packaging step.
#   * Single file the user can move, delete, or back up trivially.
#
# Usage:
#   make_appimage.sh <path/to/dist/one-link> <output.AppImage> <arch>
#
# Where <arch> is "x86_64" or "aarch64" (Linux ARM64 = aarch64 in
# AppImage convention, NOT "arm64").
set -euo pipefail

PAYLOAD_DIR="${1:?usage: make_appimage.sh <payload-dir> <out.AppImage> <arch>}"
OUT_APPIMAGE="${2:?missing output AppImage path}"
ARCH="${3:?missing arch (x86_64 or aarch64)}"

if [ ! -d "$PAYLOAD_DIR" ]; then
  echo "[appimage] FATAL: payload dir $PAYLOAD_DIR does not exist" >&2
  exit 1
fi

if [ ! -f "$PAYLOAD_DIR/one-link" ] || [ ! -x "$PAYLOAD_DIR/one-link" ]; then
  echo "[appimage] FATAL: payload must contain executable one-link" >&2
  exit 1
fi

OUT_PARENT="$(dirname "$OUT_APPIMAGE")"
if [ ! -d "$OUT_PARENT" ]; then
  echo "[appimage] FATAL: output directory $OUT_PARENT does not exist" >&2
  exit 1
fi
if [ -e "$OUT_APPIMAGE" ] || [ -L "$OUT_APPIMAGE" ]; then
  echo "[appimage] FATAL: refusing to overwrite $OUT_APPIMAGE" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASSETS="$REPO_ROOT/src/one_link/web/assets"
DESKTOP="$REPO_ROOT/packaging/linux/one-link.desktop"

# Stage the AppDir.
TMP="$(mktemp -d)"
# The path comes directly from mktemp, not an environment variable or glob.
# Always remove incomplete staging state when curl/appimagetool fails.
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM
APPDIR="$TMP/One_Link.AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib/one-link" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/512x512/apps"

# Copy the PyInstaller payload into the AppDir while preserving its executable
# bits, directory structure, and internal symlinks.
cp -a "$PAYLOAD_DIR/." "$APPDIR/usr/lib/one-link/"

# Wire the launcher: AppImage runs whatever ``AppRun`` is at the
# AppDir root. Symlink it to our actual binary inside usr/lib so
# the AppImage tooling finds an executable entry point.
cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
# Entry point for the One Link AppImage. The actual binary lives in
# usr/lib/one-link/one-link; this wrapper just forwards argv and
# adjusts $PATH so subprocesses (the daemon + supervisor it spawns)
# find their bundled siblings.
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="$HERE/usr/lib/one-link:$PATH"
exec "$HERE/usr/lib/one-link/one-link" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# .desktop file at the AppDir root + a copy in
# usr/share/applications. appimagetool reads the root one for the
# AppImage metadata.
cp "$DESKTOP" "$APPDIR/one-link.desktop"
cp "$DESKTOP" "$APPDIR/usr/share/applications/one-link.desktop"

# Icon — appimagetool wants a 256x256 PNG (or larger) at the AppDir
# root named after the binary. Prefer 512px for crisp Hi-DPI; fall
# back to whatever we have.
ICON_SRC=""
for cand in one-glyph-512.png one-glyph-256.png one-glyph.png; do
  if [ -f "$ASSETS/$cand" ]; then
    ICON_SRC="$ASSETS/$cand"
    break
  fi
done
if [ -z "$ICON_SRC" ]; then
  echo "[appimage] FATAL: no PNG icon in $ASSETS" >&2
  exit 1
fi
cp "$ICON_SRC" "$APPDIR/one-link.png"
cp "$ICON_SRC" "$APPDIR/usr/share/icons/hicolor/512x512/apps/one-link.png"
# .DirIcon is what file managers use when previewing the AppDir.
cp "$ICON_SRC" "$APPDIR/.DirIcon"

# Download an exact GitHub release *asset id*, then verify both its size and
# SHA-256 before executing it. The upstream `continuous` tag and its browser
# download URLs are mutable, so they are deliberately not build inputs.
#
# Asset provenance (audited 2026-07-22):
#   repository: AppImage/AppImageKit
#   release target: 5735cc5bed206497cddfbd2a75e1982c2606c35d
# GitHub cannot replace an asset's bytes in place: replacement requires a new
# asset id. The digest remains the fail-closed content boundary in either case.
APPIMAGETOOL_BIN="$TMP/appimagetool"
case "$ARCH" in
  x86_64)
    ASSET_ID="98605504"
    EXPECTED_BYTES="8811712"
    EXPECTED_SHA256="b90f4a8b18967545fda78a445b27680a1642f1ef9488ced28b65398f2be7add2"
    ;;
  aarch64)
    ASSET_ID="98605483"
    EXPECTED_BYTES="6115712"
    EXPECTED_SHA256="a48972e5ae91c944c5a7c80214e7e0a42dd6aa3ae979d8756203512a74ff574d"
    ;;
  *)
    echo "[appimage] FATAL: unknown arch $ARCH (want x86_64 or aarch64)" >&2
    exit 1
    ;;
esac
URL="https://api.github.com/repos/AppImage/AppImageKit/releases/assets/$ASSET_ID"
echo "[appimage] downloading appimagetool ($ARCH) ..."
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  --connect-timeout 30 --max-time 300 \
  --retry 4 --retry-all-errors \
  --header 'Accept: application/octet-stream' \
  --header 'X-GitHub-Api-Version: 2022-11-28' \
  --header 'User-Agent: One-Link-AppImage-build' \
  --output "$APPIMAGETOOL_BIN" \
  "$URL"

ACTUAL_BYTES="$(wc -c < "$APPIMAGETOOL_BIN" | tr -d '[:space:]')"
if [ "$ACTUAL_BYTES" != "$EXPECTED_BYTES" ]; then
  echo "[appimage] FATAL: appimagetool size mismatch" >&2
  echo "[appimage] expected=$EXPECTED_BYTES actual=$ACTUAL_BYTES" >&2
  exit 1
fi

ACTUAL_SHA256="$(sha256sum "$APPIMAGETOOL_BIN" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "[appimage] FATAL: appimagetool SHA-256 mismatch" >&2
  echo "[appimage] expected=$EXPECTED_SHA256 actual=$ACTUAL_SHA256" >&2
  exit 1
fi
chmod +x "$APPIMAGETOOL_BIN"

# Pack. ``--no-appstream`` skips AppStream metadata validation;
# we don't ship an AppStream feed (no app-store integration —
# AppImage is downloaded directly).
#
# On systems without FUSE (GitHub-hosted runners have FUSE but
# CI containers occasionally don't), the AppImage extraction
# needs --appimage-extract-and-run; we work around by exporting
# APPIMAGE_EXTRACT_AND_RUN=1 which tells appimagetool to run in
# fallback mode.
export APPIMAGE_EXTRACT_AND_RUN=1
ARCH="$ARCH" "$APPIMAGETOOL_BIN" --no-appstream "$APPDIR" "$OUT_APPIMAGE"

chmod +x "$OUT_APPIMAGE"
echo "[appimage] wrote $OUT_APPIMAGE ($(wc -c < "$OUT_APPIMAGE") bytes)"
