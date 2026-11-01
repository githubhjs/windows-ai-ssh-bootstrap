param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('gx10', 'osaka', 'sjamd')]
    [string]$Hub,
    [ValidateRange(0, 65535)]
    [int]$TunnelPort = 0,
    [switch]$RunAgent
)

$ErrorActionPreference = 'Stop'

if ($RunAgent) {
    $root = Join-Path $env:ProgramData 'ssh\win-tunnel'
    $profilePath = Join-Path $root "$Hub.json"
    $logPath = Join-Path $root "$Hub-agent.log"
    $ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'

    function Test-TcpEndpoint([string]$HostName, [int]$Port, [int]$TimeoutMs = 2500) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync($HostName, $Port)
            return $task.Wait($TimeoutMs) -and $client.Connected
        }
        catch { return $false }
        finally { $client.Dispose() }
    }

    while ($true) {
        try {
            $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
            if (!(Test-Path -LiteralPath $profile.KeyPath)) { throw "Tunnel key is missing: $($profile.KeyPath)" }
            $reachedAnyEndpoint = $false
            foreach ($endpoint in $profile.Endpoints) {
                if (!(Test-TcpEndpoint -HostName $endpoint.Host -Port ([int]$endpoint.Port))) { continue }
                $reachedAnyEndpoint = $true
                Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) connecting to $($endpoint.Host):$($endpoint.Port)"
                $sshArgs = @(
                    '-N', '-T', '-p', [string]$endpoint.Port, '-i', [string]$profile.KeyPath,
                    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                    '-o', 'ExitOnForwardFailure=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', "UserKnownHostsFile=$($profile.KnownHostsPath)",
                    '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
                    '-E', [string]$profile.SshLogPath,
                    # Windows sshd listens on 0.0.0.0 by default. Use a second loopback
                    # address so a WSL sshd bound to 127.0.0.1:22 cannot capture the tunnel.
                    '-R', "127.0.0.1:$($profile.TunnelPort):127.0.0.2:22",
                    "$($profile.User)@$($endpoint.Host)"
                )
                & $ssh @sshArgs
                $exitCode = $LASTEXITCODE
                Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) SSH to $($endpoint.Host) exited $exitCode"
            }

            if (!$reachedAnyEndpoint) {
                Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) no configured hub endpoint reachable; retrying in 15s"
                Start-Sleep -Seconds 15
                continue
            }
            Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) all reachable endpoint attempts ended; retrying in 30s"
        }
        catch {
            Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format o) ERROR: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 30
    }
    exit 0
}

$profiles = @{
    gx10 = @{
        User = 'win-tunnel'
        KeyName = 'id_ed25519'
        TaskName = 'AIAgent-ReverseSSH-GX10'
        Endpoints = @(
            @{ Host = '192.168.2.93'; Port = 22 }
            @{ Host = 'g.hjs.space'; Port = 1032 }
        )
        KnownHosts = @(
            '192.168.2.93 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIspW2Mazv7GP3pufcMG7ZDq+IWtMriAfn0aSGutQjKo'
            '[g.hjs.space]:1032 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIspW2Mazv7GP3pufcMG7ZDq+IWtMriAfn0aSGutQjKo'
        )
    }
    osaka = @{
        User = 'win-tunnel'
        KeyName = 'id_ed25519_osaka'
        TaskName = 'AIAgent-ReverseSSH-Osaka'
        Endpoints = @(@{ Host = 'osaka-v4.hjs.space'; Port = 22 })
        KnownHosts = @('osaka-v4.hjs.space ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMa0OqyOGPoa3VW+YyE1JtQ7661ILsnHRqsZCkhyR5rK')
    }
    sjamd = @{
        User = 'win-tunnel'
        KeyName = 'id_ed25519_sjamd'
        TaskName = 'AIAgent-ReverseSSH-SJAMD'
        Endpoints = @(@{ Host = 'sjamd-v4.hjs.space'; Port = 22 })
        KnownHosts = @('sjamd-v4.hjs.space ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII0BvBgd7GSq/LraEd2XRPX4IlEJfIHa/3VA+X8lg2A5')
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Command Prompt as Administrator and run this file again.'
}

$policy = Get-ExecutionPolicy -List
if (@($policy | Where-Object { $_.Scope -in @('MachinePolicy', 'UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) {
    throw 'Execution policy is enforced by Group Policy; no bypass was attempted.'
}

$profile = $profiles[$Hub]
$root = Join-Path $env:ProgramData 'ssh\win-tunnel'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$serverCapability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
$adminAuthorizedKeys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($serverCapability.State -ne 'Installed' -or !(Test-Path -LiteralPath $sshdConfig) -or !(Test-Path -LiteralPath $adminAuthorizedKeys) -or !$sshdService) {
    # Reuse the tested LAN installer for the inbound SSH server, public client
    # keys, key-only policy, first-run sshd_config creation, and LocalSubnet
    # firewall scope. The reverse tunnel itself does not open a WAN firewall port.
    $lanBootstrapUrl = 'https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/d04dfa4ad94ed6e0a005bc64597e9907086304f7/bootstrap-ssh.cmd'
    $lanBootstrapPath = Join-Path $env:TEMP 'bootstrap-ssh-lan-dependency.cmd'
    if ($PSVersionTable.PSVersion.Major -le 5) { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
    Invoke-WebRequest -Uri $lanBootstrapUrl -OutFile $lanBootstrapPath
    & $lanBootstrapPath
    if ($LASTEXITCODE -ne 0) { throw "The LAN SSH server setup failed with exit code $LASTEXITCODE." }
}
$keyPath = Join-Path $root $profile.KeyName
$pubPath = "$keyPath.pub"
$knownHostsPath = Join-Path $root "$Hub-known_hosts"
$sshLogPath = Join-Path $root "$Hub-ssh.log"
$agentPath = Join-Path $root "$Hub-agent.ps1"

if (!(Test-Path -LiteralPath (Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'))) {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
}
if (!(Test-Path -LiteralPath (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'))) {
    throw 'Windows OpenSSH Client did not install correctly.'
}

if (!(Test-Path -LiteralPath $keyPath)) {
    $comment = "$env:COMPUTERNAME-$Hub-reverse-tunnel"
    $cmd = "ssh-keygen.exe -q -t ed25519 -N `"`" -f `"$keyPath`" -C `"$comment`""
    & $env:ComSpec /d /c $cmd
    if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $pubPath)) {
        throw 'Could not create a passphrase-free Ed25519 tunnel key.'
    }
}

if ($TunnelPort -eq 0) {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $sha = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($uuid)) }
    finally { $hasher.Dispose() }
    $TunnelPort = 20000 + ([BitConverter]::ToUInt32($sha, 0) % 40000)
}

$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$keyAcl = Get-Acl -LiteralPath $keyPath
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access)) { [void]$keyAcl.RemoveAccessRuleAll($rule) }
$keyAcl.SetOwner($systemSid)
$systemRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $systemSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.AccessControlType]::Allow
)
$keyAcl.SetAccessRule($systemRule)
Set-Acl -LiteralPath $keyPath -AclObject $keyAcl

$knownHosts = ($profile.KnownHosts -join "`r`n") + "`r`n"
if (Test-Path -LiteralPath $knownHostsPath) {
    # The file contains only public host keys. Restore the inherited admin ACL
    # before replacing it so an elevated rerun can update a prior SYSTEM-owned file.
    $existingHostFileAcl = Get-Acl -LiteralPath $knownHostsPath
    $existingHostFileAcl.SetOwner($administratorsSid)
    $existingHostFileAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $knownHostsPath -AclObject $existingHostFileAcl
}
[IO.File]::WriteAllText($knownHostsPath, $knownHosts, [Text.Encoding]::ASCII)
Copy-Item -LiteralPath $PSCommandPath -Destination $agentPath -Force

$hostFileAcl = Get-Acl -LiteralPath $knownHostsPath
$hostFileAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($hostFileAcl.Access)) { [void]$hostFileAcl.RemoveAccessRuleAll($rule) }
$hostFileAcl.SetOwner($systemSid)
$hostFileAcl.SetAccessRule($systemRule)
$administratorsRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $administratorsSid,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.AccessControlType]::Allow
)
$hostFileAcl.SetAccessRule($administratorsRule)
Set-Acl -LiteralPath $knownHostsPath -AclObject $hostFileAcl

$config = [ordered]@{
    Hub = $Hub
    User = $profile.User
    KeyPath = $keyPath
    KnownHostsPath = $knownHostsPath
    SshLogPath = $sshLogPath
    TunnelPort = $TunnelPort
    Endpoints = $profile.Endpoints
}
$profilePath = Join-Path $root "$Hub.json"
$config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $profilePath -Encoding UTF8

$action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agentPath`" -RunAgent -Hub $Hub"
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $profile.TaskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $profile.TaskName
Start-Sleep -Seconds 3

$pubKey = (Get-Content -LiteralPath $pubPath -Raw).Trim()
$fingerprint = (& (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe') -lf $pubPath 2>&1 | Out-String).Trim()
$taskState = (Get-ScheduledTask -TaskName $profile.TaskName).State
$agentLog = Join-Path $root "$Hub-agent.log"

Write-Host ''
Write-Host '=== Reverse SSH setup ===' -ForegroundColor Cyan
Write-Host "Hub: $Hub"
Write-Host "Task: $($profile.TaskName) ($taskState)"
Write-Host "Tunnel listener on hub: 127.0.0.1:$TunnelPort"
Write-Host "Device: $env:COMPUTERNAME"
Write-Host "Client key fingerprint: $fingerprint"
Write-Host "Agent log: $agentLog"
Write-Host 'Client public key (safe to share for one-time server enrollment):' -ForegroundColor Yellow
Write-Host $pubKey
Write-Host 'This does not expose the private key. The hub must authorize this key with a matching per-key loopback port restriction before the tunnel can connect.'
