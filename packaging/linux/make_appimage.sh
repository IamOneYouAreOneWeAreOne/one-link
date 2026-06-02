#!/usr/bin/env bash
# Build a Linux AppImage from the PyInstaller bundle.
#
# AppImage is the most universal Linux install format: a single
# self-contained executable file that runs across distros (Ubuntu,
# Debian, Fedora, Arch, etc.) without dependency-hell or root
# install. Compare:
#
#   .deb       — Debian + Ubuntu only, needs apt + sudo
#   .rpm       — Fedora + RHEL + openSUSE only
#   Flatpak    — needs Flatpak runtime pre-installed
#   Snap       — Ubuntu-centric, snapd dependency
#   AppImage   — single file, chmod +x, double-click. Done.
#
# Design contract — same "for the people, not corp" stance as the
# Windows installer + macOS .dmg:
#
#   * No root required. AppImage runs from the user's Downloads or
#     ~/Applications folder.
#   * No package-manager integration (the user can drop a .desktop
#     file via the in-app autostart feature; the AppImage doesn't
#     mutate the system).
#   * No telemetry. No update-framework injection. The in-app
#     updater handles updates on its own terms.
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

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ASSETS="$REPO_ROOT/src/one_link/web/assets"
DESKTOP="$REPO_ROOT/packaging/linux/one-link.desktop"

# Stage the AppDir.
TMP="$(mktemp -d)"
APPDIR="$TMP/One_Link.AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/512x512/apps"

# Copy the PyInstaller payload into the AppDir. ``cp -aL`` preserves
# permissions + dereferences symlinks (AppImage can't easily ship
# dangling symlinks).
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

# Download appimagetool for the matching arch. The official release
# stays at the AppImage/AppImageKit GH releases. We cache it under
# /tmp so subsequent CI runs reuse it.
APPIMAGETOOL_BIN="$TMP/appimagetool"
case "$ARCH" in
  x86_64)
    URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
    ;;
  aarch64)
    URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-aarch64.AppImage"
    ;;
  *)
    echo "[appimage] FATAL: unknown arch $ARCH (want x86_64 or aarch64)" >&2
    exit 1
    ;;
esac
echo "[appimage] downloading appimagetool ($ARCH) ..."
curl -fsSL -o "$APPIMAGETOOL_BIN" "$URL"
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
rm -rf "$TMP"
