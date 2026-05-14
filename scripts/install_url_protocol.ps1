# Register the one-link:// URL protocol for the current Windows user.
#
# Usage:
#   pip install -e .
#   .\scripts\install_url_protocol.ps1

$ErrorActionPreference = "Stop"

$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) {
    Write-Error "python is not on PATH. Install Python 3.11+ first."
    exit 1
}

$probe = & $pythonExe -c "import one_link, sys; sys.stdout.write(one_link.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "one_link is not installed in this Python. Run: pip install -e . first."
    exit 1
}

$root = "HKCU:\Software\Classes\one-link"
$commandKey = Join-Path $root "shell\open\command"
New-Item -Path $commandKey -Force | Out-Null
New-ItemProperty -Path $root -Name "URL Protocol" -Value "" -PropertyType String -Force | Out-Null
Set-ItemProperty -Path $root -Name "(default)" -Value "URL:One Link Protocol"
$command = ('"{0}" -m one_link.cli open-url "%1"' -f $pythonExe)
Set-ItemProperty -Path $commandKey -Name "(default)" -Value $command

Write-Host "Registered one-link:// for One Link $probe"
Write-Host "Command: $command"
