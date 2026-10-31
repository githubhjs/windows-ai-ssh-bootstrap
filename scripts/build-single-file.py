#!/usr/bin/env python3
"""Embed bootstrap-ssh.ps1 as a compressed payload in a self-contained CMD launcher."""

from __future__ import annotations

import base64
import gzip
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "bootstrap-ssh.ps1"
OUTPUT = ROOT / "bootstrap-ssh.cmd"
MARKER = "::BEGIN_PS_PAYLOAD::"

LAUNCHER = r'''@echo off
setlocal
set "BOOTSTRAP_BUNDLE_FILE=%~f0"

rem Check policy and elevation before extracting or running the embedded PowerShell payload.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $policy=Get-ExecutionPolicy -List; $policy | Format-Table -AutoSize; if (@($policy | Where-Object { $_.Scope -in @('MachinePolicy','UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) { Write-Error 'Execution policy is enforced by Group Policy. Ask the device administrator; no bypass was attempted.'; exit 3 }; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=[Security.Principal.WindowsPrincipal]::new($identity); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'Open Command Prompt as Administrator and run this file again.'; exit 2 }; $raw=[IO.File]::ReadAllText($env:BOOTSTRAP_BUNDLE_FILE,[Text.Encoding]::ASCII); $markerMatch=[regex]::Match($raw,'(?m)^::BEGIN_PS_PAYLOAD::\r?$'); if (-not $markerMatch.Success) { Write-Error 'Embedded bootstrap payload marker was not found.'; exit 4 }; $payload=($raw.Substring($markerMatch.Index+$markerMatch.Length) -replace '\s',''); if ($payload -notmatch '^[A-Za-z0-9+/]+={0,2}$') { Write-Error 'Embedded payload contains invalid Base64 characters; download the latest CMD file again.'; exit 4 }; try { $bytes=[Convert]::FromBase64String($payload) } catch { Write-Error 'Embedded payload is malformed; download the latest CMD file again.'; exit 4 }; $inputStream=[IO.MemoryStream]::new($bytes); $gzip=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress); $reader=[IO.StreamReader]::new($gzip,[Text.Encoding]::UTF8); $source=$reader.ReadToEnd(); $temp=Join-Path $env:TEMP ('bootstrap-ssh-'+[guid]::NewGuid().ToString('N')+'.ps1'); $code=1; try { [IO.File]::WriteAllText($temp,$source,[Text.UTF8Encoding]::new($false)); & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $temp; $code=$LASTEXITCODE } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }; exit $code"
set "RC=%ERRORLEVEL%"
exit /b %RC%

'''


def main() -> None:
    source = SOURCE.read_bytes()
    payload = base64.b64encode(gzip.compress(source, compresslevel=9, mtime=0)).decode("ascii")
    wrapped = "\n".join(payload[i : i + 76] for i in range(0, len(payload), 76))
    OUTPUT.write_text(LAUNCHER + MARKER + "\n" + wrapped + "\n", encoding="ascii", newline="\r\n")
    print(f"Wrote {OUTPUT.name}: source={len(source)} bytes, compressed={len(base64.b64decode(payload))} bytes")


if __name__ == "__main__":
    main()
