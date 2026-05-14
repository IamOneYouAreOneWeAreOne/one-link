#!/usr/bin/env bash
set -euo pipefail

# Install a per-user macOS one-link:// URL handler.
#
# macOS requires URL schemes to be declared by an app bundle. This script
# creates a tiny AppleScript app in ~/Applications that delegates to the
# current Python's One Link CLI.

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python)}"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "python is not on PATH. Install Python 3.11+ first." >&2
  exit 1
fi

"${PYTHON_BIN}" -c 'import one_link' >/dev/null

APP_DIR="${HOME}/Applications/One Link URL Handler.app"
CONTENTS="${APP_DIR}/Contents"
MACOS="${CONTENTS}/MacOS"
mkdir -p "${MACOS}"

cat > "${CONTENTS}/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>One Link URL Handler</string>
  <key>CFBundleIdentifier</key><string>com.onelink.urlhandler</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>one-link-url-handler</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>One Link</string>
      <key>CFBundleURLSchemes</key><array><string>one-link</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST

cat > "${MACOS}/one-link-url-handler" <<SH
#!/usr/bin/env bash
exec "${PYTHON_BIN}" -m one_link.cli open-url "\$1"
SH
chmod +x "${MACOS}/one-link-url-handler"

/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "${APP_DIR}" >/dev/null 2>&1 || true

echo "Registered one-link:// with ${APP_DIR}"
