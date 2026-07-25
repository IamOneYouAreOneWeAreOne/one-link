#!/usr/bin/env bash
set -euo pipefail

# Install a per-user Linux desktop handler for one-link:// URLs (LF-only script).

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python)}"
if [[ -z "${PYTHON_BIN}" ]]; then
  echo "python is not on PATH. Install Python 3.11+ first." >&2
  exit 1
fi

"${PYTHON_BIN}" -c 'import one_link' >/dev/null

APP_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"
DESKTOP_FILE="${APP_DIR}/one-link-url-handler.desktop"
mkdir -p "${APP_DIR}"

cat > "${DESKTOP_FILE}" <<DESKTOP
[Desktop Entry]
Type=Application
Name=One Link URL Handler
Exec=${PYTHON_BIN} -m one_link.cli open-url %u
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/one-link;
DESKTOP

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "${APP_DIR}" >/dev/null 2>&1 || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default one-link-url-handler.desktop x-scheme-handler/one-link
fi

echo "Registered one-link:// with ${DESKTOP_FILE}"
