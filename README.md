# Windows AI-agent SSH bootstrap

An idempotent PowerShell bootstrap for enabling key-only SSH access to a Windows device so Codex,
Claude Code, or another authorized agent can administer it over a trusted LAN/VPN.

## Security defaults

- Installs Microsoft's Windows OpenSSH Server capability.
- Adds one **public** key for the account running the elevated script.
- Disables SSH password and keyboard-interactive authentication; requires public-key authentication.
- Restricts SSH logins to that Windows account.
- Allows TCP/22 only from `LocalSubnet` by default, on the Private and Domain firewall profiles.
- Explicitly refuses unrestricted source ranges such as `0.0.0.0/0`, `::/0`, or `Any`.
- Disables existing enabled inbound allow rules for exact TCP/22 and replaces them with its scoped
  local firewall rule.
- Does **not** create router port forwarding, public DNS, a VPN, or a public SSH service.

Use a private LAN or VPN for remote agents. If a source must be added, specify its observed source IP
or a narrow CIDR. Do not expose TCP/22 to the public internet.

## Run it

Open **PowerShell as Administrator** on the Windows device. Download and inspect the script first:

```powershell
$url = 'https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/main/bootstrap-ssh.ps1'
$script = Join-Path $env:TEMP 'bootstrap-ssh.ps1'
Invoke-WebRequest -Uri $url -OutFile $script
Unblock-File -Path $script
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
notepad $script
```

Then run it with a trusted agent's public key. The public key is safe to pass on the command line;
never use a private key here.

```powershell
$key = (Get-Content "$HOME\.ssh\id_ed25519.pub" -Raw).Trim()
& $script -AuthorizedKey $key
```

The default source range is `LocalSubnet`. To allow a client on another private/VPN network, pass
its exact source IP or a narrow CIDR:

```powershell
& $script -AuthorizedKey $key -AllowedRemoteAddress @('192.168.2.93', '10.20.0.0/24')
```

If the key is already stored in a file, use `-AuthorizedKeyPath 'C:\path\to\agent.pub'` instead.
The script prompts for a public key if neither key parameter is supplied.

## Verify from the allowed client

```sh
ssh <windows-user>@<windows-ip> hostname
```

For diagnostics on Windows, check `Get-Service sshd`, the `AIAgent-OpenSSH-Limited` firewall rule,
and `C:\ProgramData\ssh\sshd_config`. The script creates a timestamped config backup before
editing it. Re-run the same command to update the key or allowed sources. Centrally managed
firewall policies may still add separate rules and should be reviewed by the device administrator.

## Access the script

- Repository: <https://github.com/githubhjs/windows-ai-ssh-bootstrap>
- Raw script: <https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/main/bootstrap-ssh.ps1>

Review the script before running it. This project does not contain device credentials, private SSH
keys, passwords, or host-specific network details.

## Limitations

- Run from an elevated PowerShell session with administrator rights and internet access to the
  Microsoft capability source.
- The script configures only the current account. Other accounts are intentionally not enabled.
- Firewall defaults assume local/VPN access on Private or Domain profiles. Public-profile access
  requires explicitly passing `-FirewallProfile Public` and a narrow source address.
- Remote access may require a VPN or an existing private tunnel. This script intentionally does not
  alter routers, NAT, DNS, or Cloudflare settings.
