#!/usr/bin/env python3
"""Build self-contained, per-hub CMD launchers for the reverse-SSH installer."""

from __future__ import annotations

import base64
import gzip
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "bootstrap-ssh-remote.ps1"
MARKER = "::BEGIN_PS_PAYLOAD::"

BOOTSTRAP = r"""$ErrorActionPreference = 'Stop'
$policy = Get-ExecutionPolicy -List
$policy | Format-Table -AutoSize
if (@($policy | Where-Object { $_.Scope -in @('MachinePolicy','UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) {
    Write-Error 'Execution policy is enforced by Group Policy. Ask the device administrator; no bypass was attempted.'
    exit 3
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Open Command Prompt as Administrator and run this file again.'
    exit 2
}
$raw = [IO.File]::ReadAllText($env:BOOTSTRAP_BUNDLE_FILE, [Text.Encoding]::ASCII)
$markerMatch = [regex]::Match($raw, '(?m)^::BEGIN_PS_PAYLOAD::\r?$')
if (-not $markerMatch.Success) {
    Write-Error 'Embedded bootstrap payload marker was not found.'
    exit 4
}
$payload = $raw.Substring($markerMatch.Index + $markerMatch.Length) -replace '\s', ''
if ($payload -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
    Write-Error 'Embedded payload contains invalid Base64 characters; download the latest CMD file again.'
    exit 4
}
try { $bytes = [Convert]::FromBase64String($payload) }
catch {
    Write-Error 'Embedded payload is malformed; download the latest CMD file again.'
    exit 4
}
$inputStream = [IO.MemoryStream]::new($bytes)
$gzip = [IO.Compression.GzipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
$reader = [IO.StreamReader]::new($gzip, [Text.Encoding]::UTF8)
$source = $reader.ReadToEnd()
$temp = Join-Path $env:TEMP ('bootstrap-ssh-remote-' + [guid]::NewGuid().ToString('N') + '.ps1')
$code = 1
try {
    [IO.File]::WriteAllText($temp, $source, [Text.UTF8Encoding]::new($false))
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $temp -Hub $env:BOOTSTRAP_HUB
    $code = $LASTEXITCODE
}
finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
exit $code
"""

LAUNCHER = """@echo off
setlocal
set "BOOTSTRAP_BUNDLE_FILE=%~f0"
set "BOOTSTRAP_HUB=__HUB__"
set "BOOTSTRAP_COMMAND=__ENCODED_BOOTSTRAP__"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand %BOOTSTRAP_COMMAND%
set "RC=%ERRORLEVEL%"
exit /b %RC%

"""


def build(hub: str) -> Path:
    payload = base64.b64encode(gzip.compress(SOURCE.read_bytes(), compresslevel=9, mtime=0)).decode("ascii")
    wrapped_payload = "\r\n".join(textwrap.wrap(payload, 76))
    encoded_bootstrap = base64.b64encode(BOOTSTRAP.encode("utf-16le")).decode("ascii")
    launcher = LAUNCHER.replace("__HUB__", hub).replace("__ENCODED_BOOTSTRAP__", encoded_bootstrap)
    output = ROOT / f"bootstrap-ssh-remote-{hub}.cmd"
    output.write_text(launcher + MARKER + "\r\n" + wrapped_payload + "\r\n", encoding="ascii", newline="")
    return output


def main() -> None:
    for hub in ("gx10", "osaka", "sjamd"):
        output = build(hub)
        print(f"Wrote {output.name}: {output.stat().st_size} bytes")


if __name__ == "__main__":
    main()
