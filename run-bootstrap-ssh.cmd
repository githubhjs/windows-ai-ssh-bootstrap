@echo off
setlocal

rem Check admin rights and policy overrides before starting the PowerShell script.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p=Get-ExecutionPolicy -List; $p | Format-Table -AutoSize; if (@($p | Where-Object { $_.Scope -in @('MachinePolicy','UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) { Write-Error 'Execution policy is set by Group Policy. Ask the device administrator; no bypass was attempted.'; exit 3 }; $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=[Security.Principal.WindowsPrincipal]::new($id); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'Open Command Prompt as Administrator and run this launcher again.'; exit 2 }"
if errorlevel 1 exit /b %errorlevel%

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bootstrap-ssh.ps1" %*
exit /b %errorlevel%
