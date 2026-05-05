# Create a One_link desktop shortcut on Windows.
#
# Targets python.exe with `-m one_link.cli chat` so it works whether or not
# the bundled exe is signed/allowed by Defender / Application Control.
#
# Usage (from a Windows PowerShell prompt):
#   pip install -e .
#   .\scripts\install_desktop_shortcut.ps1

$ErrorActionPreference = "Stop"

$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "One_link.lnk"

# Find the Python that has one_link installed.
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Write-Error "python is not on PATH. Install Python 3.11+ first."
    exit 1
}

# Sanity-check that the Python we found actually has one_link installed.
$check = & $pythonExe -c "import one_link, sys; sys.stdout.write(one_link.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "one_link is not installed in this Python. Run: pip install -e .  first."
    exit 1
}
Write-Host "Found one_link $check at $pythonExe"

# Create the shortcut.
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($shortcutPath)
$lnk.TargetPath = $pythonExe
$lnk.Arguments = "-m one_link.cli chat"
$lnk.WorkingDirectory = "$env:USERPROFILE"
$lnk.Description = "One_link — peer-to-peer LAN chat + file sync"
$lnk.WindowStyle = 1  # Normal window
$lnk.Save()

Write-Host "Created shortcut: $shortcutPath"
Write-Host "Double-click it to start One_link chat."
