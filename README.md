# Windows AI-agent SSH bootstrap

An idempotent PowerShell bootstrap for Josh's device fleet. It enables key-only SSH access to a
Windows device so Codex, Claude Code, or another authorized agent on GX10 can administer it over a
trusted LAN/VPN.

## Security defaults

- Installs Microsoft's Windows OpenSSH Server capability.
- Adds GX10's **public** Ed25519 client key for the account running the elevated script. The private
  key remains on GX10. You can still pass another public key explicitly.
- Disables SSH password and keyboard-interactive authentication; requires public-key authentication.
- Restricts SSH logins to that Windows account.
- Allows TCP/22 only from `LocalSubnet` by default, on the Private and Domain firewall profiles.
- Explicitly refuses unrestricted source ranges such as `0.0.0.0/0`, `::/0`, or `Any`.
- Replaces existing exact TCP/22 allow rules with its scoped rule. It checks effective rules for
  broader multi-port/Any-port allows and stops before changing SSH if one could widen access or is
  centrally managed.
- Stops before making changes when an enabled inbound block rule covers SSH, since a block can
  override the new allow rule. This check is deliberately conservative: it stops for any enabled
  inbound block filter that could match TCP/22, regardless of its address or profile scope; review
  the named rule manually rather than deleting it automatically.
- When checking existing TCP/22 rules, also checks the Windows Firewall application and service
  filters. A broad port/address rule limited to another executable, packaged app, or service is not
  mistaken for an SSH rule. Filters are read from the same ActiveStore as the rules. An empty set of
  block rules is handled normally.
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

If PowerShell reports that script execution is disabled, run it from that same elevated window
after setting the process-scoped policy above. This applies only to the current PowerShell process;
it does not change the machine or user execution policy. For a script already saved as
`C:\temp\bootstrap-ssh.ps1`, the two commands are:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& 'C:\temp\bootstrap-ssh.ps1'
```

Do not use `Unrestricted` or change `LocalMachine` policy for this setup. If Group Policy overrides
the process setting, stop and ask the device administrator rather than trying to bypass that policy.
The script requires an elevated shell. It uses GX10's embedded public key by default, so there is no
paste prompt. This public repository is personalized for Josh's devices: running it authorizes the
holder of GX10's matching private key to sign in to the configured Windows account. Do not run it on
someone else's computer.

For the easiest one-file setup, download [`bootstrap-ssh.cmd`](bootstrap-ssh.cmd), open **Command
Prompt as Administrator** in its folder, and run `bootstrap-ssh.cmd`. It contains a compressed copy
of the PowerShell implementation, checks elevation and execution-policy Group Policy overrides,
then extracts to a temporary `.ps1` and runs only that PowerShell process with `-ExecutionPolicy
Bypass`. It removes the temporary file afterward. It stops if MachinePolicy or UserPolicy is
configured; it does not try to evade organization policy. Regenerate it from the source PS1 with
`python scripts/build-single-file.py` after changing the PowerShell implementation.

The two-file alternative is `run-bootstrap-ssh.cmd` beside `bootstrap-ssh.ps1`; it applies the same
checks but requires both files to stay together.

For a single download, get [`dist/windows-ai-ssh-bootstrap.zip`](dist/windows-ai-ssh-bootstrap.zip),
extract it, then run `run-bootstrap-ssh.cmd` from an elevated Command Prompt in the extracted folder.
The archive contains both launch options, the PowerShell implementation, and these instructions.

The default embedded client public key is GX10's existing Ed25519 key. It has no passphrase, and the
bootstrap installs it automatically. A Windows-host-generated key is not appropriate here: the
Windows machine is the SSH server, while GX10 is the SSH client.

```powershell
# Optional: replace the default GX10 key with another client public key.
& $script -AuthorizedKeyPath 'C:\path\to\agents.pub'
```

The default source range is `LocalSubnet`. To allow a client on another private/VPN network, pass
its exact source IP or a narrow CIDR:

```powershell
& $script -AuthorizedKeyPath 'C:\path\to\agents.pub' -AllowedRemoteAddress @('192.168.2.93', '10.20.0.0/24')
```

If the target already has a locally managed exact TCP/22 rule that can match `sshd`, the script
disables that rule and replaces it with the requested source/profile scope. This prevents the old
rule from continuing to allow SSH from `Any`. It refuses to modify centrally managed exact rules,
and stops for broader multi-port rules or matching inbound block rules because those need separate
review.

For multiple agent keys in one file, use `-AuthorizedKeyPath 'C:\path\to\agents.pub'`.

## Verify from the allowed client

```sh
ssh <windows-user>@<windows-ip> hostname
```

For diagnostics on Windows, check `Get-Service sshd`, the `AIAgent-OpenSSH-Limited` firewall rule,
and `C:\ProgramData\ssh\sshd_config`. The script creates a timestamped config backup before
editing it. Re-run the same command to update the key or allowed sources. Centrally managed
firewall policies may still add separate rules and should be reviewed by the device administrator.
Scope comparison is deliberately conservative and textual; semantically equivalent but differently
written IP/CIDR ranges may require resolving the conflicting rule manually.

## Access the script

- Repository: <https://github.com/githubhjs/windows-ai-ssh-bootstrap>
- Raw script: <https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/main/bootstrap-ssh.ps1>

Review the script before running it. This project does not contain device credentials, private SSH
keys, passwords, or host-specific network details.

## Limitations

- Run from an elevated PowerShell session with administrator rights and internet access to the
  Microsoft capability source.
- The script configures only the current account. Other Windows accounts are intentionally not enabled.
- Firewall defaults assume local/VPN access on Private or Domain profiles. Public-profile access
  requires explicitly passing `-FirewallProfile Public` and a narrow source address.
- Remote access may require a VPN or an existing private tunnel. This script intentionally does not
  alter routers, NAT, DNS, or Cloudflare settings.
