#!/usr/bin/env bash
# Package a One Link .app into a user-friendly .dmg disk image.
#
# Design contract (mirrors the Windows installer's "for the people,
# not corp" stance):
#
#   * The .dmg shows the One Link .app + a symlink to /Applications.
#     User drags the app over the symlink — the canonical macOS
#     install gesture, no extra UI to read or click.
#   * NO EULA. NO licensing dialog. NO "register your copy" prompt.
#     NO telemetry opt-in. The disk image is the install.
#   * NO Sparkle update-framework injection. The in-app updater
#     handles that path on its own terms when the user opts in.
#   * Compressed UDZO (the standard read-only-zlib .dmg format) so
#     the download stays small. ~25 MB for the bundle vs ~80 MB
#     uncompressed.
#
# Usage:
#   make_dmg.sh <path/to/One Link.app> <output.dmg> <volume-name>
#
# Example:
#   make_dmg.sh dist/one-link.app dist/one-link-macos-arm64.dmg \
#               "One Link"
set -euo pipefail

APP_PATH="${1:?usage: make_dmg.sh <app-path> <out-dmg> <vol-name>}"
OUT_DMG="${2:?missing output .dmg path}"
VOL_NAME="${3:?missing volume name}"

if [ ! -d "$APP_PATH" ]; then
  echo "[dmg] FATAL: $APP_PATH is not a directory (.app bundle expected)" >&2
  exit 1
fi

# Stage the .dmg contents in a temp dir: app + symlink to
# /Applications. hdiutil takes a single source folder.
STAGE="$(mktemp -d)/dmg-stage"
mkdir -p "$STAGE"
# Copy preserving symlinks + permissions. ditto is macOS-native
# and respects the .app extended attributes (xattr quarantine flag,
# code-sign signatures) that ``cp -R`` can strip.
ditto "$APP_PATH" "$STAGE/$(basename "$APP_PATH")"
ln -s /Applications "$STAGE/Applications"

# Create the compressed read-only .dmg in one call. UDZO = the
# canonical "shrunk read-only" format; UDBZ would be ~5% smaller
# but reads slower on older Macs. The size delta isn't worth it for
# a 25-MB image.
rm -f "$OUT_DMG"
hdiutil create \
  -volname "$VOL_NAME" \
  -srcfolder "$STAGE" \
  -ov \
  -format UDZO \
  -fs HFS+ \
  -imagekey zlib-level=9 \
  "$OUT_DMG"

# Verify the produced image — catches the very rare case of a corrupted
# write before we ship it.
hdiutil verify "$OUT_DMG"

rm -rf "$(dirname "$STAGE")"
echo "[dmg] wrote $OUT_DMG ($(wc -c < "$OUT_DMG") bytes)"
