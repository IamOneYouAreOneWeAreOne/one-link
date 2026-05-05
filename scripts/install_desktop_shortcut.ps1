# Create a One_link desktop shortcut on Windows.
#
# Targets python.exe with `-m one_link.cli app` so it works whether or not
# the bundled exe is signed/allowed by Defender / Application Control.
# Uses the ONE Glyph icon shipped inside the installed package.
#
# Usage (from a Windows PowerShell prompt):
#   pip install -e .
#   .\scripts\install_desktop_shortcut.ps1

$ErrorActionPreference = "Stop"

$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "One Link.lnk"

# Hard rule: one and only one One Link desktop shortcut.
# Remove EVERY pre-existing shortcut whose name starts with "One " or "One_"
# before creating the canonical one. No duplicates. Ever.
Get-ChildItem -Path $desktop -Filter "*.lnk" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "One *.lnk" -or $_.Name -like "One_*.lnk" } |
    ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        Write-Host "Removed stale shortcut: $($_.Name)"
    }

# Find the Python that has one_link installed.
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Write-Error "python is not on PATH. Install Python 3.11+ first."
    exit 1
}

# Sanity-check that the Python we found actually has one_link installed,
# and discover the icon path inside the package. Prefer the freshly-named
# `one-link-app.ico` which sidesteps Windows shell icon-cache holds on the
# legacy `one-glyph.ico` path.
$probe = & $pythonExe -c @"
import one_link, pathlib, sys
sys.stdout.write(one_link.__version__)
sys.stdout.write('|')
base = pathlib.Path(one_link.__file__).parent / 'web' / 'assets'
ico = base / 'one-link-app.ico'
if not ico.exists():
    ico = base / 'one-glyph.ico'
sys.stdout.write(str(ico))
"@ 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "one_link is not installed in this Python. Run: pip install -e .  first."
    exit 1
}
$parts = $probe -split '\|'
$version = $parts[0]
$iconPath = $parts[1]
Write-Host "Found one_link $version at $pythonExe"
if (Test-Path $iconPath) {
    Write-Host "Icon: $iconPath"
} else {
    Write-Host "Icon not found at $iconPath (shortcut will use python.exe default icon)"
}

# Create the shortcut.
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($shortcutPath)
$lnk.TargetPath = $pythonExe
$lnk.Arguments = "-m one_link.cli app"
$lnk.WorkingDirectory = "$env:USERPROFILE"
$lnk.Description = "One Link - peer-to-peer LAN chat + file sync"
$lnk.WindowStyle = 1  # Normal window
if (Test-Path $iconPath) {
    $lnk.IconLocation = "$iconPath,0"
}
$lnk.Save()

Write-Host "Created shortcut: $shortcutPath"
Write-Host "Double-click it to open One_link."
