#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Windows OpenSSH Server for key-only, source-restricted access.
.DESCRIPTION
    Installs the Windows OpenSSH Server capability, adds public keys for the
    current Windows account, disables password/interactive authentication, and
    creates a Private/Domain firewall rule restricted to the supplied IPs/CIDRs.
    It does not configure router port forwarding, public DNS, or WAN exposure.
    If execution is blocked before this script starts, use bootstrap-ssh.cmd (standalone) or
    run-bootstrap-ssh.cmd beside this file; execution policy is checked by the launchers.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string[]] $AuthorizedKey,

    [Parameter()]
    [string] $AuthorizedKeyPath,

    [Parameter()]
    [string[]] $AllowedRemoteAddress = @('LocalSubnet'),

    [Parameter()]
    [ValidateSet('Domain', 'Private', 'Public')]
    [string[]] $FirewallProfile = @('Private', 'Domain')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AllowedRemoteAddress {
    param([string[]] $Addresses)

    if (-not $Addresses -or $Addresses.Count -eq 0) {
        throw 'At least one source address is required.'
    }

    foreach ($address in $Addresses) {
        if ($address -eq 'LocalSubnet') { continue }
        if ($address -in @('Any', '*', '0.0.0.0/0', '::/0')) {
            throw "Unrestricted source '$address' is not allowed. Use LocalSubnet, an IP, or a narrow CIDR."
        }

        $parts = $address -split '/', 2
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) {
            throw "'$address' is not an IP address or CIDR. Hostnames are intentionally not accepted."
        }
        if ($parts.Count -eq 2) {
            $prefix = 0
            if (-not [int]::TryParse($parts[1], [ref]$prefix)) {
                throw "Invalid CIDR prefix in '$address'."
            }
            $maxPrefix = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if ($prefix -lt 1 -or $prefix -gt $maxPrefix) {
                throw "CIDR '$address' must use a prefix from 1 through $maxPrefix; unrestricted routes are refused."
            }
        }
    }
}

function Test-PortFilterIncludesSsh {
    param($PortFilter)

    if ($PortFilter.Protocol -notin @('TCP', '6', 'Any', '256')) { return $false }
    foreach ($entry in @($PortFilter.LocalPort)) {
        foreach ($portSpec in ([string]$entry -split ',')) {
            $portSpec = $portSpec.Trim()
            if ($portSpec -eq 'Any' -or $portSpec -eq '22') { return $true }
            if ($portSpec -match '^(\d+)-(\d+)$') {
                if ([int]$Matches[1] -le 22 -and [int]$Matches[2] -ge 22) { return $true }
            }
        }
    }
    return $false
}

function Test-RemoteScopeContained {
    param([string[]] $Existing, [string[]] $Requested)

    foreach ($source in $Existing) {
        if ($Requested -notcontains $source) { return $false }
    }
    return $true
}

function Test-StringSetEqual {
    param([string[]] $Left, [string[]] $Right)

    $leftSet = @($Left | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $rightSet = @($Right | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object -Unique)
    return [string]::Join("`n", $leftSet) -ceq [string]::Join("`n", $rightSet)
}

function Test-FirewallRuleCouldMatchSshd {
    param(
        $Rule,
        [string] $SshdPath
    )

    # Firewall rules are conjunctive: an Any-port/Any-address rule limited to
    # another executable, packaged app, or service cannot open SSH for sshd.
    $applicationFilters = @($Rule | Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($filter in $applicationFilters) {
        $package = [string]$filter.Package
        if ($package -and $package -notin @('Any', '*')) { return $false }

        $program = [string]$filter.Program
        if ($program -and $program -notin @('Any', '*')) {
            $expandedProgram = [Environment]::ExpandEnvironmentVariables($program).Trim('"')
            $expandedSshdPath = [Environment]::ExpandEnvironmentVariables($SshdPath).Trim('"')
            if (-not [string]::Equals($expandedProgram, $expandedSshdPath, [StringComparison]::OrdinalIgnoreCase)) {
                return $false
            }
        }
    }

    $serviceFilters = @($Rule | Get-NetFirewallServiceFilter -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($filter in $serviceFilters) {
        $service = [string]$filter.Service
        if ($service -and $service -notin @('Any', '*', 'sshd')) { return $false }
    }

    return $true
}

function Set-SshdGlobalDirective {
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [string] $Name,
        [string] $Value
    )

    $matchIndex = $Lines.Count
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*Match\s+') {
            $matchIndex = $i
            break
        }
    }

    for ($i = $matchIndex - 1; $i -ge 0; $i--) {
        if ($Lines[$i] -match "^\s*#?\s*$([regex]::Escape($Name))\s+") {
            $Lines.RemoveAt($i)
            $matchIndex--
        }
    }
    $Lines.Insert($matchIndex, "$Name $Value")
}

Assert-AllowedRemoteAddress -Addresses $AllowedRemoteAddress

# Windows Firewall rules are additive. Query the store once, then filter in
# PowerShell so an empty Block-rule result is a normal empty array, not a CIM
# query failure. Include application and service filters before assessing scope.
$activeInboundRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' })
$firewallAllowRules = @($activeInboundRules | Where-Object { $_.Action -eq 'Allow' })
$firewallBlockRules = @($activeInboundRules | Where-Object { $_.Action -eq 'Block' })
$sshdPathForFirewallCheck = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
$exactSshRuleNames = [System.Collections.Generic.List[string]]::new()
$broaderFirewallConflicts = [System.Collections.Generic.List[string]]::new()
$blockingFirewallConflicts = [System.Collections.Generic.List[string]]::new()
foreach ($candidate in $firewallAllowRules) {
    $portFilter = $candidate | Get-NetFirewallPortFilter -PolicyStore ActiveStore
    if (-not (Test-PortFilterIncludesSsh -PortFilter $portFilter)) { continue }
    if (-not (Test-FirewallRuleCouldMatchSshd -Rule $candidate -SshdPath $sshdPathForFirewallCheck)) { continue }

    $isExactTcp22 = $portFilter.Protocol -in @('TCP', '6') -and @($portFilter.LocalPort).Count -eq 1 -and $portFilter.LocalPort -eq '22'
    if ($isExactTcp22) {
        $addressFilter = $candidate | Get-NetFirewallAddressFilter -PolicyStore ActiveStore
        $existingProfiles = @(([string]$candidate.Profile -split '[,\s]+') | Where-Object { $_ })
        $sameSources = Test-StringSetEqual -Left @($addressFilter.RemoteAddress) -Right $AllowedRemoteAddress
        $sameProfiles = Test-StringSetEqual -Left $existingProfiles -Right $FirewallProfile
        if ($candidate.PolicyStoreSourceType -ne 'Local') {
            $broaderFirewallConflicts.Add("$($candidate.Name) [TCP/22 rule managed by $($candidate.PolicyStoreSourceType)]")
        } else {
            if (-not $sameSources -or -not $sameProfiles) {
                Write-Host "Will replace local TCP/22 rule '$($candidate.Name)' (sources: $($addressFilter.RemoteAddress -join ', '); profiles: $($existingProfiles -join ', ')) with the requested restricted rule." -ForegroundColor Yellow
            }
            $exactSshRuleNames.Add($candidate.Name)
        }
        continue
    }

    $addressFilter = $candidate | Get-NetFirewallAddressFilter -PolicyStore ActiveStore
    if (-not (Test-RemoteScopeContained -Existing @($addressFilter.RemoteAddress) -Requested $AllowedRemoteAddress)) {
        $broaderFirewallConflicts.Add("$($candidate.Name) [ports: $($portFilter.LocalPort); sources: $($addressFilter.RemoteAddress -join ', ')]")
    }
}
# Conservative by design: any enabled inbound block filter that could match
# TCP/22 causes a stop, even if its address/profile scope may be disjoint.
foreach ($candidate in $firewallBlockRules) {
    $portFilter = $candidate | Get-NetFirewallPortFilter -PolicyStore ActiveStore
    if (Test-PortFilterIncludesSsh -PortFilter $portFilter) {
        if (-not (Test-FirewallRuleCouldMatchSshd -Rule $candidate -SshdPath $sshdPathForFirewallCheck)) { continue }
        $addressFilter = $candidate | Get-NetFirewallAddressFilter -PolicyStore ActiveStore
        $blockingFirewallConflicts.Add("$($candidate.Name) [ports: $($portFilter.LocalPort -join ', '); sources: $($addressFilter.RemoteAddress -join ', ')]")
    }
}
if ($broaderFirewallConflicts.Count -gt 0) {
    $conflicts = $broaderFirewallConflicts -join '; '
    throw "Existing inbound allow rule(s) conflict with the requested SSH firewall scope: $conflicts. No SSH/firewall changes were made. Review, narrow, or remove those rules, then rerun."
}
if ($blockingFirewallConflicts.Count -gt 0) {
    $conflicts = $blockingFirewallConflicts -join '; '
    throw "Existing inbound block rule(s) cover SSH port 22: $conflicts. Block rules can override this bootstrap's allow rule. Resolve them before rerunning. No SSH/firewall changes were made."
}

if ((-not $AuthorizedKey -or $AuthorizedKey.Count -eq 0) -and $AuthorizedKeyPath) {
    if (-not (Test-Path -LiteralPath $AuthorizedKeyPath -PathType Leaf)) {
        throw "Public key file not found: $AuthorizedKeyPath"
    }
    $AuthorizedKey = @(Get-Content -LiteralPath $AuthorizedKeyPath)
}
if (-not $AuthorizedKey -or $AuthorizedKey.Count -eq 0) {
    $AuthorizedKey = @((Read-Host 'Paste one SSH public key (ssh-ed25519 ...; public key only)'))
}
$publicKeys = @($AuthorizedKey | ForEach-Object { $_ -split '\r?\n' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' })
if (-not $publicKeys -or $publicKeys.Count -eq 0) {
    throw 'No public keys were supplied.'
}
foreach ($publicKey in $publicKeys) {
    if ($publicKey -notmatch '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa)\s+[A-Za-z0-9+/]+={0,2}(\s+.*)?$') {
        throw 'A supplied value is not a supported OpenSSH public-key line. Do not provide a private key.'
    }
}

$capabilityName = 'OpenSSH.Server~~~~0.0.1.0'
$capability = Get-WindowsCapability -Online -Name $capabilityName
if ($capability.State -ne 'Installed') {
    Write-Host 'Installing Windows OpenSSH Server capability...'
    Add-WindowsCapability -Online -Name $capabilityName | Out-Null
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
$isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$accountName = $env:USERNAME
if ([string]::IsNullOrWhiteSpace($accountName)) { throw 'Could not determine the current Windows account.' }

$sshDataDirectory = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshDataDirectory 'sshd_config'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "OpenSSH configuration was not found at $configPath"
}

if ($isAdministrator) {
    $authorizedKeysPath = Join-Path $sshDataDirectory 'administrators_authorized_keys'
    $aclSpec = @('*S-1-5-18:F', '*S-1-5-32-544:F')
} else {
    $sshUserDirectory = Join-Path $env:USERPROFILE '.ssh'
    New-Item -ItemType Directory -Path $sshUserDirectory -Force | Out-Null
    $authorizedKeysPath = Join-Path $sshUserDirectory 'authorized_keys'
    $aclSpec = @("*$($currentIdentity.User.Value):F", '*S-1-5-18:F', '*S-1-5-32-544:F')
}

if (-not (Test-Path -LiteralPath $authorizedKeysPath)) {
    New-Item -ItemType File -Path $authorizedKeysPath -Force | Out-Null
}
$existingKeys = @(Get-Content -LiteralPath $authorizedKeysPath -ErrorAction SilentlyContinue)
$addedKeyCount = 0
foreach ($publicKey in $publicKeys) {
    if ($existingKeys -notcontains $publicKey) {
        Add-Content -LiteralPath $authorizedKeysPath -Value $publicKey -Encoding ascii
        $existingKeys += $publicKey
        $addedKeyCount++
    }
}
$icaclsArgs = @($authorizedKeysPath, '/inheritance:r', '/grant:r') + $aclSpec
& "$env:WINDIR\System32\icacls.exe" @icaclsArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure ACLs on $authorizedKeysPath" }

$backupPath = "$configPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $configPath -Destination $backupPath
$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in Get-Content -LiteralPath $configPath) { $lines.Add($line) }
Set-SshdGlobalDirective -Lines $lines -Name 'PubkeyAuthentication' -Value 'yes'
Set-SshdGlobalDirective -Lines $lines -Name 'PasswordAuthentication' -Value 'no'
Set-SshdGlobalDirective -Lines $lines -Name 'KbdInteractiveAuthentication' -Value 'no'
Set-SshdGlobalDirective -Lines $lines -Name 'AuthenticationMethods' -Value 'publickey'
Set-SshdGlobalDirective -Lines $lines -Name 'AllowUsers' -Value $accountName
Set-Content -LiteralPath $configPath -Value $lines -Encoding ascii

$sshdPath = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
& $sshdPath -t -f $configPath
if ($LASTEXITCODE -ne 0) {
    Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
    throw "sshd_config validation failed. Original config restored from $backupPath"
}

# Replace local exact TCP/22 rules that can match sshd with the requested scoped
# rule. Centrally managed rules and wider multi-port rules were rejected above.
foreach ($ruleNameToDisable in ($exactSshRuleNames | Select-Object -Unique)) {
    Get-NetFirewallRule -PolicyStore PersistentStore -Name $ruleNameToDisable -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule | Out-Null
}

$ruleName = 'AIAgent-OpenSSH-Limited'
$oldRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if ($oldRule) { $oldRule | Remove-NetFirewallRule }
New-NetFirewallRule -Name $ruleName `
    -DisplayName 'AI agent SSH (restricted sources)' `
    -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 `
    -Action Allow -RemoteAddress $AllowedRemoteAddress -Profile $FirewallProfile | Out-Null

Set-Service -Name sshd -StartupType Automatic
Restart-Service -Name sshd

Write-Host ''
Write-Host 'OpenSSH Server is configured for public-key-only login.' -ForegroundColor Green
Write-Host "Windows account: $accountName"
Write-Host "Authorized key file: $authorizedKeysPath"
Write-Host "Public keys added: $addedKeyCount"
Write-Host "Allowed source addresses: $($AllowedRemoteAddress -join ', ')"
Write-Host "Firewall profiles: $($FirewallProfile -join ', ')"
Write-Host 'Firewall rule: AIAgent-OpenSSH-Limited (TCP/22)'
Write-Host "Config backup: $backupPath"
Write-Host 'No router port forwarding or public exposure was configured.'
Write-Host 'From an allowed client, verify with: ssh <windows-user>@<device-ip> hostname'
